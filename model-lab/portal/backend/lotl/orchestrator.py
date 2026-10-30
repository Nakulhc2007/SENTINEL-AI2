from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from .agents import run_five_agents, verification_agent
from .engine import BASELINES, build_baseline
from .storage import connect, new_id, now_iso


def _decoded_events(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    decoded = []
    for row in rows:
        event = json.loads(row['event_json'])
        event.setdefault('organization_domain', row['organization_domain'])
        decoded.append(event)
    return decoded


def get_events(domain: str | None = None, limit: int = 2000, include_baseline: bool = True) -> list[dict[str, Any]]:
    sql = 'SELECT * FROM lotl_events'
    args: list[Any] = []
    where = []
    if domain:
        where.append('organization_domain=?')
        args.append(domain)
    if not include_baseline:
        where.append('synthetic_baseline=0')
    if where:
        sql += ' WHERE ' + ' AND '.join(where)
    sql += ' ORDER BY timestamp DESC LIMIT ?'
    args.append(max(1, min(5000, limit)))
    return _decoded_events(rows_to_dict(sql, tuple(args)))


def rows_to_dict(sql: str, args: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
    with connect() as connection:
        return [dict(row) for row in connection.execute(sql, args).fetchall()]


def get_maintenance(domain: str | None = None) -> list[dict[str, Any]]:
    sql = 'SELECT * FROM lotl_maintenance'
    args: tuple[Any, ...] = ()
    if domain:
        sql += ' WHERE organization_domain=?'
        args = (domain,)
    sql += ' ORDER BY starts_at DESC LIMIT 200'
    rows = rows_to_dict(sql, args)
    for row in rows:
        row['authorized_users'] = json.loads(row.pop('authorized_users_json'))
        row['approved_actions'] = json.loads(row.pop('approved_actions_json'))
        row['approved_resources'] = json.loads(row.pop('approved_resources_json'))
    return rows


def _audit(run_id: str, incident_id: str | None, actor: str, action: str, details: str, domain: str) -> None:
    with connect() as connection:
        connection.execute('INSERT INTO lotl_audit(audit_id,run_id,incident_id,actor,action,details,created_at,organization_domain) VALUES(?,?,?,?,?,?,?,?)',
                           (new_id('AUD'), run_id, incident_id, actor, action, details[:2000], now_iso(), domain))


def run_workflow(scenario_id: str, name: str, events: list[dict[str, Any]], domain: str, maintenance_override: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    if not events:
        raise ValueError('Add at least one activity event.')
    run_id = new_id('RUN')
    ids = [event['event_id'] for event in events]
    with connect() as connection:
        placeholders = ','.join('?' for _ in ids)
        duplicates = {row[0] for row in connection.execute(f'SELECT event_id FROM lotl_events WHERE event_id IN ({placeholders})', ids).fetchall()}
    fresh_events = [event for event in events if event['event_id'] not in duplicates]
    duplicate_count = len(events) - len(fresh_events)
    if not fresh_events:
        return {'run_id': None, 'duplicate_events': len(events), 'message': 'These event IDs were already processed. No duplicate incident was created.'}

    maintenance = maintenance_override if maintenance_override is not None else get_maintenance(domain)
    history = get_events(domain=domain, limit=5000)
    baselines = {username: build_baseline(history, username) for username in {event['username'] for event in fresh_events}}
    results = run_five_agents(fresh_events, baselines, maintenance, history)
    # Re-run the detection stage with a rolling history so multi-session drift in one batch accumulates.
    suspicious = [row['detection']['detection']['suspicious'] for row in results]
    if any('grad-session-' in event.get('session_id', '') for event in fresh_events):
        from .agents import detection_agent
        detection_rows = detection_agent(fresh_events, baselines, maintenance, history)
        for item, detected in zip(results, detection_rows):
            item['detection'] = {'event': detected['event'], 'baseline': detected['baseline'], 'detection': detected['detection']}
        from .agents import investigation_agent, risk_assessment_agent, response_agent
        investigations = investigation_agent(detection_rows, history)
        assessments = [row['detection'] for row in detection_rows]
        risks = risk_assessment_agent(assessments)
        responses = response_agent(assessments, risks, fresh_events)
        for item, investigation, risk, response in zip(results, investigations, risks, responses):
            item['investigation'], item['risk_assessment'], item['response'] = investigation, risk, response
            item['verification'] = verification_agent({'decision': 'pending' if response['status'] == 'pending_human_approval' else 'monitor', 'decided_at': None if response['status'] == 'pending_human_approval' else datetime.now(timezone.utc).isoformat(timespec='seconds')})
        suspicious = [item['detection']['detection']['suspicious'] for item in results]

    grouped: dict[str, list[int]] = {}
    for index, item in enumerate(results):
        if item['detection']['detection']['suspicious']:
            grouped.setdefault(item['detection']['event']['username'], []).append(index)
    incidents = []
    for username, indexes in grouped.items():
        best = max(indexes, key=lambda index: results[index]['risk_assessment']['score'])
        selected = results[best]
        incident_id = new_id('LOT')
        related_events = [results[index]['detection']['event'] for index in indexes]
        status = 'Awaiting human approval'
        summary = {
            'incident_id': incident_id, 'run_id': run_id, 'scenario_id': scenario_id, 'name': name,
            'username': username, 'organization_domain': domain, 'created_at': now_iso(),
            'event_ids': [row['event_id'] for row in related_events], 'events': related_events,
            'detection': [results[index]['detection']['detection'] for index in indexes],
            'baseline': selected['detection']['baseline'], 'investigation': selected['investigation'],
            'risk_assessment': selected['risk_assessment'], 'response': selected['response'],
            'verification': selected['verification'], 'business_impact': selected['response'],
            'status': status,
        }
        incidents.append(summary)

    classifications = []
    with connect() as connection:
        for event, item in zip(fresh_events, results):
            detected = item['detection']['detection']
            classification = 'suspicious' if detected['suspicious'] else 'expected maintenance' if detected['expected_maintenance'] else 'normal'
            stored_event = event | {'assessment': detected, 'deviation_count': detected['deviation_count'], 'classification': classification, 'run_id': run_id}
            connection.execute('INSERT OR IGNORE INTO lotl_events(event_id,timestamp,username,organization_domain,session_id,synthetic_baseline,event_json,run_id) VALUES(?,?,?,?,?,?,?,?)',
                               (event['event_id'], event['timestamp'], event['username'], domain, event.get('session_id', 'default-session'), 0, json.dumps(stored_event), run_id))
            classifications.append(classification)
        for incident in incidents:
            connection.execute('INSERT INTO lotl_incidents(incident_id,run_id,organization_domain,username,created_at,risk_score,risk_level,status,incident_json) VALUES(?,?,?,?,?,?,?,?,?)',
                               (incident['incident_id'], run_id, domain, incident['username'], incident['created_at'], incident['risk_assessment']['score'], incident['risk_assessment']['level'], incident['status'], json.dumps(incident)))
        outcome = 'suspicious' if incidents else 'expected maintenance' if 'expected maintenance' in classifications else 'normal'
        result_payload = {'run_id': run_id, 'scenario_id': scenario_id, 'name': name, 'organization_domain': domain, 'created_at': now_iso(), 'outcome': outcome, 'event_count': len(fresh_events), 'classifications': classifications, 'workflow': results, 'incidents': incidents, 'verification_status': 'awaiting human decision' if incidents else 'verified'}
        connection.execute('INSERT INTO lotl_runs(run_id,scenario_id,organization_domain,name,created_at,outcome,result_json) VALUES(?,?,?,?,?,?,?)',
                           (run_id, scenario_id, domain, name, result_payload['created_at'], outcome, json.dumps(result_payload)))
    stages = [
        ('Detection Agent', f'Classified {len(fresh_events)} event(s); {sum(classification == "suspicious" for classification in classifications)} suspicious.'),
        ('Investigation Agent', 'Correlated events by account, source IP, device, resource, session, and timestamp.'),
        ('Risk Assessment Agent', 'Assigned transparent heuristic scores and recorded their evidence factors.'),
        ('Response Agent', 'Prepared a business-impact-aware recommendation; impactful actions await a human.'),
        ('Verification Agent', 'Recorded the expected simulated outcome or marked the response pending approval.'),
    ]
    for agent, detail in stages:
        _audit(run_id, incidents[0]['incident_id'] if incidents else None, 'SENTINEL demo orchestrator', agent, detail, domain)
    for incident in incidents:
        _audit(run_id, incident['incident_id'], 'SENTINEL demo orchestrator', 'Incident created', f"{incident['username']} · {incident['risk_assessment']['score']}/100 · {incident['risk_assessment']['explanation']}", domain)
    return result_payload | {'duplicate_events': duplicate_count}


def decide(incident_id: str, decision: str, approver: str, note: str) -> dict[str, Any]:
    with connect() as connection:
        row = connection.execute('SELECT * FROM lotl_incidents WHERE incident_id=?', (incident_id,)).fetchone()
        if not row:
            return {}
        incident = json.loads(row['incident_json'])
        if row['status'] not in ('Awaiting human approval', 'Needs further review'):
            return {'error': f"This incident is already marked {row['status']}."}
        now = now_iso()
        record = {'decision': decision, 'approver': approver, 'note': note, 'decided_at': now, 'simulated': True}
        incident['human_approval'] = record
        if decision == 'approve':
            verification = verification_agent(record)
            incident['verification'] = verification
            incident['status'] = 'Approved · simulation verified'
        elif decision == 'reject':
            incident['verification'] = {'status': 'not_executed', 'result': 'Human reviewer rejected the recommendation; no change was made.', 'verified_at': now, 'simulated': True}
            incident['status'] = 'Rejected · no action taken'
        else:
            incident['status'] = 'Needs further review'
        connection.execute('UPDATE lotl_incidents SET status=?,incident_json=?,decision_json=? WHERE incident_id=?', (incident['status'], json.dumps(incident), json.dumps(record), incident_id))
        run_id = row['run_id']
        audit_action = {'approve': 'Approved simulated response', 'reject': 'Rejected response recommendation', 'review': 'Marked for further review'}[decision]
        connection.execute('INSERT INTO lotl_audit(audit_id,run_id,incident_id,actor,action,details,created_at,organization_domain) VALUES(?,?,?,?,?,?,?,?)', (new_id('AUD'), run_id, incident_id, approver, audit_action, f"{incident['response']['action']} · {note or 'No additional note'} · Demo only; no external system changed.", now, row['organization_domain']))
        run_row = connection.execute('SELECT result_json FROM lotl_runs WHERE run_id=?', (run_id,)).fetchone()
        if run_row:
            run_payload = json.loads(run_row['result_json'])
            run_payload['incidents'] = [incident if item['incident_id'] == incident_id else item for item in run_payload.get('incidents', [])]
            connection.execute('UPDATE lotl_runs SET result_json=? WHERE run_id=?', (json.dumps(run_payload), run_id))
    return incident


def dashboard_data(domain: str | None = None) -> dict[str, Any]:
    events = get_events(domain, limit=5000)
    activity = [event for event in events if not event.get('synthetic_baseline')]
    incidents_sql = 'SELECT * FROM lotl_incidents'
    args: tuple[Any, ...] = ()
    if domain:
        incidents_sql += ' WHERE organization_domain=?'
        args = (domain,)
    incidents_sql += ' ORDER BY created_at DESC LIMIT 200'
    incidents = []
    for row in rows_to_dict(incidents_sql, args):
        incidents.append(json.loads(row['incident_json']))
    runs_sql = 'SELECT * FROM lotl_runs'
    if domain:
        runs_sql += ' WHERE organization_domain=?'
    runs_sql += ' ORDER BY created_at DESC LIMIT 100'
    runs = [json.loads(row['result_json']) for row in rows_to_dict(runs_sql, args)]
    audits_sql = 'SELECT * FROM lotl_audit'
    if domain:
        audits_sql += ' WHERE organization_domain=?'
        audit_args = (domain,)
    else:
        audit_args = ()
    audits_sql += ' ORDER BY created_at DESC LIMIT 300'
    audits = rows_to_dict(audits_sql, audit_args)
    domains = [domain] if domain else sorted({'banking', 'healthcare', 'education', 'government', 'corporate', 'manufacturing', 'retail', 'public-services'})
    baselines = []
    for scoped_domain in domains:
        domain_events = [event for event in events if event.get('organization_domain') == scoped_domain]
        names = sorted(set(BASELINES) | {event['username'] for event in domain_events if not event.get('synthetic_baseline')})
        baselines.extend(build_baseline(domain_events, username) | {'organization_domain': scoped_domain} for username in names)
    schedules = get_maintenance(domain)
    pending = sum(incident['status'] == 'Awaiting human approval' for incident in incidents)
    critical_high = sum(incident['risk_assessment']['level'] in ('High', 'Critical') for incident in incidents if incident['status'] == 'Awaiting human approval')
    return {'metrics': {'total_events': len(activity), 'normal_activity': sum(event.get('classification') in ('normal', 'expected maintenance') for event in activity), 'suspicious_activity': sum(event.get('classification') == 'suspicious' for event in activity), 'open_incidents': pending, 'high_critical_incidents': critical_high, 'maintenance_events': sum(event.get('classification') == 'expected maintenance' for event in activity), 'gradual_deviation_alerts': sum(any(factor['factor'] == 'Gradual deviation across sessions' for factor in incident['risk_assessment']['factors']) for incident in incidents)}, 'events': activity[:300], 'incidents': incidents, 'runs': runs, 'baselines': baselines, 'maintenance': schedules, 'audit': audits}
