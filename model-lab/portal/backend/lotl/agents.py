from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

from .engine import build_baseline, evaluate_event


def detection_agent(events: list[dict[str, Any]], baselines: dict[str, dict[str, Any]], maintenance: list[dict[str, Any]], history: list[dict[str, Any]]) -> list[dict[str, Any]]:
    findings = []
    rolling_history = list(history)
    for event in events:
        baseline = baselines.get(event['username']) or build_baseline(rolling_history, event['username'])
        result = evaluate_event(event, baseline, maintenance, rolling_history)
        findings.append({'event': event, 'baseline': baseline, 'detection': result})
        rolling_history.append(event | {'deviation_count': result['deviation_count']})
    return findings


def investigation_agent(findings: list[dict[str, Any]], history: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_user: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in history + [item['event'] for item in findings]:
        by_user[row['username']].append(row)
    output = []
    for item in findings:
        event = item['event']
        related = [row for row in by_user[event['username']] if row['timestamp'] <= event['timestamp']]
        related = sorted(related, key=lambda row: row['timestamp'])[-20:]
        timeline = [{key: row.get(key) for key in ('event_id', 'timestamp', 'username', 'source_ip', 'device', 'action', 'resource', 'permission_level', 'outcome')} for row in related]
        output.append({'status': 'complete', 'observed_facts': [f'{event["username"]} performed {event["action"]} on {event["resource"]}.', f'Source {event["source_ip"]}, device {event["device"]}, at {event["timestamp"]}.'], 'interpretation': 'Activity differs from this account’s normal profile; confirm intent with the resource owner.' if item['detection']['suspicious'] else 'The activity is consistent with the available baseline and approved context.', 'related_event_count': len(related), 'involved_users': sorted({row['username'] for row in related}), 'timeline': timeline})
    return output


def risk_assessment_agent(detection: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [{'status': 'complete', 'score': row['risk_score'], 'level': row['risk_level'], 'confidence': row['confidence'], 'missing_evidence': row['missing_evidence'], 'factors': row['factors'], 'explanation': '; '.join(f"{factor['factor']} (+{factor['points']}): {factor['evidence']}" for factor in row['factors'] if factor['points']) or 'No material baseline deviations were observed.', 'heuristic_notice': 'Illustrative heuristic score for this synthetic demo; not a validated attack probability.'} for row in detection]


def response_agent(detection: list[dict[str, Any]], risk: list[dict[str, Any]], events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    recommendations = []
    for result, score, event in zip(detection, risk, events):
        value = score['score']
        criticality = event['business_criticality'].lower()
        if not result['suspicious']:
            action, urgency, benefit, disruption = 'Record activity and continue monitoring', 'Routine', 'Preserves an audit record without interrupting expected work.', 'Minimal'
        elif value < 40:
            action, urgency, benefit, disruption = 'Continue monitoring and request identity confirmation if repeated', 'Low', 'Adds context before taking disruptive action.', 'Minimal'
        elif value < 65:
            action, urgency, benefit, disruption = 'Notify the security team and verify the user’s identity', 'Within 1 business day', 'Confirms whether the activity was authorized.', 'Low'
        elif value < 85:
            action, urgency, benefit, disruption = 'Review the account permissions and related sessions with the owner', 'Prompt review', 'Limits exposure by identifying excess access while preserving the account.', 'Low to medium'
        else:
            action, urgency, benefit, disruption = 'Request human review of the privileged session and consider a temporary restriction', 'Immediate human review', 'Can contain high-impact activity if the owner cannot verify it.', 'Medium to high'
        if criticality in ('high', 'critical') and result['suspicious'] and value < 85:
            urgency = 'Prompt review'
        recommendations.append({'status': 'pending_human_approval' if result['suspicious'] else 'monitoring', 'action': action, 'reason': 'Selected from the observed baseline differences, resource sensitivity, and current evidence.', 'security_benefit': benefit, 'operational_disruption': disruption, 'business_importance': criticality.title(), 'estimated_downtime': 'None expected' if value < 85 else 'Possible short interruption if a restriction is approved', 'urgency': urgency, 'cost_level': 'High' if value >= 85 else 'Medium' if value >= 60 else 'Low', 'less_disruptive_option': 'Monitor and verify with the owner before applying any restriction.'})
    return recommendations


def verification_agent(decision: dict[str, Any]) -> dict[str, Any]:
    approved = decision['decision'] == 'approve'
    if decision['decision'] == 'monitor':
        return {'status': 'verified', 'result': 'No action was required; the expected demo outcome is continued monitoring.', 'verified_at': decision['decided_at'], 'simulated': True}
    if decision['decision'] == 'pending':
        return {'status': 'awaiting_human_decision', 'result': 'Response remains pending human approval; no change was made.', 'verified_at': None, 'simulated': True}
    return {'status': 'verified' if approved else 'not_executed', 'result': 'The requested demo response was recorded as simulated; no external account or system was changed.' if approved else 'No response was executed. The decision and reason were recorded for review.', 'verified_at': decision['decided_at'], 'simulated': True}


def run_five_agents(events: list[dict[str, Any]], baselines: dict[str, dict[str, Any]], maintenance: list[dict[str, Any]], history: list[dict[str, Any]]) -> list[dict[str, Any]]:
    detection = detection_agent(events, baselines, maintenance, history)
    investigations = investigation_agent(detection, history)
    assessments = [row['detection'] for row in detection]
    risks = risk_assessment_agent(assessments)
    responses = response_agent(assessments, risks, events)
    return [{'detection': detected, 'investigation': investigation, 'risk_assessment': risk, 'response': response, 'verification': verification_agent({'decision': 'pending' if response['status'] == 'pending_human_approval' else 'monitor', 'decided_at': None if response['status'] == 'pending_human_approval' else datetime.now(timezone.utc).isoformat(timespec='seconds')})}
            for detected, investigation, risk, response in zip(detection, investigations, risks, responses)]
