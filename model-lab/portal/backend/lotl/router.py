from __future__ import annotations

import json
import hashlib
import logging
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import ValidationError

from .orchestrator import dashboard_data, decide, run_workflow
from .scenarios import scenario_bundle
from .schemas import ActivityEvent, DecisionInput, MaintenanceInput
from .storage import connect, new_id, now_iso

log = logging.getLogger('sentinel.lotl')
router = APIRouter(prefix='/api/lotl', tags=['Living Off the Land demo'])
VALID_DOMAINS = {'banking', 'healthcare', 'education', 'government', 'corporate', 'manufacturing', 'retail', 'public-services'}
SCENARIO_NAMES = {
    'normal-administration': 'Normal administration',
    'suspicious-night-activity': 'Suspicious night activity',
    'gradual-credential-misuse': 'Gradual credential misuse',
    'approved-maintenance': 'Approved maintenance',
}


def _domain(value: str | None) -> str:
    domain = value or 'corporate'
    if domain not in VALID_DOMAINS:
        raise HTTPException(status_code=422, detail='Choose one of the eight demo domains.')
    return domain


def _normalize_record(raw: dict[str, Any], default_domain: str | None = None) -> ActivityEvent:
    source = {str(key).strip().lower().replace(' ', '_').replace('-', '_'): value for key, value in raw.items()}
    if any(any(secret_word in key for secret_word in ('password', 'token', 'secret', 'credential')) for key in source):
        raise HTTPException(status_code=422, detail='Credential or secret fields are not accepted. Remove them before importing activity logs.')
    aliases = {
        'user': 'username', 'account': 'username', 'role': 'user_role', 'device_name': 'device',
        'process': 'process_category', 'tool': 'process_category', 'tool_category': 'process_category',
        'event': 'action', 'event_type': 'action', 'operation': 'action', 'target': 'resource',
        'document_path': 'resource', 'file_path': 'resource',
        'permission': 'permission_level', 'data_volume': 'data_volume_mb', 'export_volume_mb': 'data_volume_mb',
        'maintenance_schedule_ref': 'maintenance_ref', 'change_reference': 'maintenance_ref',
        'eventid': 'event_id', 'user_name': 'username', 'sourceip': 'source_ip',
        'success': 'login_success', 'login_result': 'outcome', 'organization': 'organization_domain', 'domain': 'organization_domain',
    }
    for old, new in aliases.items():
        if old in source and new not in source:
            source[new] = source[old]
    if not source.get('event_id') and source.get('timestamp'):
        identity = '|'.join(str(source.get(key, '')) for key in ('timestamp', 'username', 'user', 'source_ip', 'device', 'action', 'resource', 'session_id'))
        source['event_id'] = f'UPLOAD-{hashlib.sha256(identity.encode()).hexdigest()[:18].upper()}'
    if not source.get('timestamp'):
        raise HTTPException(status_code=422, detail='Each activity record needs a valid timestamp.')
    if 'action' not in source or not str(source['action']).strip():
        raise HTTPException(status_code=422, detail='Each activity record needs an action or event type.')
    if default_domain and not source.get('organization_domain'):
        source['organization_domain'] = default_domain
    if 'organization_domain' in source:
        source['organization_domain'] = str(source['organization_domain']).strip().lower().replace('_', '-')
        if source['organization_domain'] not in VALID_DOMAINS:
            raise HTTPException(status_code=422, detail=f"Unknown demo domain: {source['organization_domain']}")
    for key in ('login_success',):
        value = source.get(key)
        if isinstance(value, str):
            normalized = value.strip().lower()
            if normalized in ('true', '1', 'yes', 'success', 'succeeded'):
                source[key] = True
            elif normalized in ('false', '0', 'no', 'failure', 'failed'):
                source[key] = False
            else:
                source[key] = None
    if source.get('data_volume_mb') is None or (isinstance(source.get('data_volume_mb'), str) and not source['data_volume_mb'].strip()):
        source['data_volume_mb'] = 0
    if not str(source.get('maintenance_ref') or '').strip():
        source['maintenance_ref'] = None
    for key in ('document_hash_before', 'document_hash_after'):
        if not str(source.get(key) or '').strip():
            source[key] = None
    for key, fallback in (('source_ip', 'unknown'), ('device', 'unknown'), ('outcome', 'success'), ('process_category', 'administrative_tool'), ('permission_level', 'standard'), ('resource', 'unknown')):
        if not str(source.get(key) or '').strip():
            source[key] = fallback
    return ActivityEvent.model_validate(source)


def _save_maintenance(window: dict[str, Any], domain: str) -> None:
    with connect() as connection:
        connection.execute('''INSERT OR REPLACE INTO lotl_maintenance(
            maintenance_id,organization_domain,starts_at,ends_at,authorized_users_json,
            approved_actions_json,approved_resources_json,description,change_reference,status,created_at
        ) VALUES(?,?,?,?,?,?,?,?,?,?,?)''', (
            window['maintenance_id'], domain, window['starts_at'], window['ends_at'],
            json.dumps(window['authorized_users']), json.dumps(window['approved_actions']),
            json.dumps(window['approved_resources']), window['description'], window['change_reference'],
            window.get('status', 'approved'), now_iso(),
        ))


@router.get('/overview')
def lotl_overview(domain: str | None = None) -> dict[str, Any]:
    if domain:
        _domain(domain)
    return dashboard_data(domain)


@router.get('/scenarios')
def list_scenarios() -> list[dict[str, str]]:
    descriptions = {
        'normal-administration': 'Routine work during usual hours using a familiar device and approved change.',
        'suspicious-night-activity': 'New device and address, privilege change, and sensitive exports outside a maintenance window.',
        'gradual-credential-misuse': 'Small account deviations accumulate across sessions and several days.',
        'approved-maintenance': 'Authorized user, actions, resource, change reference, and schedule are compared.',
    }
    return [{'id': key, 'name': value, 'description': descriptions[key]} for key, value in SCENARIO_NAMES.items()]


@router.post('/scenarios/{scenario_id}/run')
def run_scenario(scenario_id: str, domain: str = 'corporate') -> dict[str, Any]:
    domain = _domain(domain)
    try:
        scenario = scenario_bundle(scenario_id, organization_domain=domain)
    except KeyError:
        raise HTTPException(status_code=404, detail='Unknown LotL demo scenario.')
    for window in scenario['maintenance']:
        _save_maintenance(window, domain)
    try:
        return run_workflow(scenario_id, scenario['name'], scenario['events'], domain, scenario['maintenance'] + [window for window in _scheduled(domain) if window['maintenance_id'] not in {item['maintenance_id'] for item in scenario['maintenance']}])
    except Exception as error:
        log.exception('LotL scenario failed: %s', scenario_id)
        raise HTTPException(status_code=500, detail='The demo workflow could not complete. Review the local service log and try again.') from error


def _scheduled(domain: str) -> list[dict[str, Any]]:
    from .orchestrator import get_maintenance
    return get_maintenance(domain)


@router.post('/events')
def ingest_events(body: dict[str, Any]) -> dict[str, Any]:
    records = body.get('events')
    if not isinstance(records, list) or not 1 <= len(records) <= 1000:
        raise HTTPException(status_code=422, detail='Submit between 1 and 1,000 activity records in an events array.')
    default_domain = body.get('organization_domain')
    if default_domain:
        default_domain = _domain(str(default_domain))
    try:
        events = [_normalize_record(record, default_domain).model_dump(mode='json') for record in records if isinstance(record, dict)]
        if len(events) != len(records):
            raise HTTPException(status_code=422, detail='Every event must be a JSON object.')
        domains = {event['organization_domain'] for event in events}
        runs = []
        for domain in sorted(domains):
            group = [event for event in events if event['organization_domain'] == domain]
            runs.append(run_workflow('authorized-log-ingestion', 'Uploaded synthetic activity logs', group, domain))
        return {'runs': runs, 'accepted_events': sum(item.get('event_count', 0) for item in runs), 'duplicate_events': sum(item.get('duplicate_events', 0) for item in runs)}
    except ValidationError as error:
        raise HTTPException(status_code=422, detail=error.errors(include_input=False)) from error
    except HTTPException:
        raise
    except Exception as error:
        log.exception('LotL event ingestion failed')
        raise HTTPException(status_code=500, detail='The synthetic event batch could not be processed.') from error


@router.post('/maintenance')
def create_maintenance(body: MaintenanceInput, domain: str = 'corporate') -> dict[str, Any]:
    domain = _domain(domain)
    try:
        start = datetime.strptime(f'{body.date} {body.start_time}', '%Y-%m-%d %H:%M').replace(tzinfo=timezone.utc)
        end = datetime.strptime(f'{body.date} {body.end_time}', '%Y-%m-%d %H:%M').replace(tzinfo=timezone.utc)
    except ValueError as error:
        raise HTTPException(status_code=422, detail='Enter a valid date and 24-hour start and end times.') from error
    if end <= start:
        raise HTTPException(status_code=422, detail='The maintenance end time must be after its start time on the same date.')
    window = {'maintenance_id': body.maintenance_id or new_id('MAINT'), 'organization_domain': domain,
              'starts_at': start.isoformat(timespec='seconds'), 'ends_at': end.isoformat(timespec='seconds'),
              'authorized_users': [value.strip() for value in body.authorized_users if value.strip()],
              'approved_actions': [value.strip() for value in body.approved_actions if value.strip()],
              'approved_resources': [value.strip() for value in body.approved_resources if value.strip()],
              'description': body.description.strip(), 'change_reference': body.change_reference.strip(), 'status': 'approved'}
    if not window['authorized_users'] or not window['approved_actions'] or not window['approved_resources']:
        raise HTTPException(status_code=422, detail='Add at least one authorized user, action, and resource.')
    _save_maintenance(window, domain)
    with connect() as connection:
        connection.execute('INSERT INTO lotl_audit(audit_id,actor,action,details,created_at,organization_domain) VALUES(?,?,?,?,?,?)', (new_id('AUD'), 'Local demo administrator', 'Maintenance schedule created', f"{window['change_reference']} · {window['description']}", now_iso(), domain))
    return window


@router.post('/incidents/{incident_id}/decision')
def incident_decision(incident_id: str, body: DecisionInput) -> dict[str, Any]:
    result = decide(incident_id, body.decision, body.approver, body.note)
    if not result:
        raise HTTPException(status_code=404, detail='LotL incident not found.')
    if result.get('error'):
        raise HTTPException(status_code=409, detail=result['error'])
    return result
