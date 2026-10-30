from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from typing import Any

BASELINES: dict[str, dict[str, Any]] = {
    'admin.alex': {
        'role': 'Systems Administrator', 'normal_hours': [8, 18],
        'resources': ['/admin/health', '/admin/jobs', '/admin/users'],
        'actions': ['view_status', 'restart_service', 'rotate_logs'],
        'devices': ['ADM-WS-01'], 'ips': ['10.0.0.10'], 'usual_permission': 'administrator',
        'business_criticality': 'high', 'activity_per_day': 6,
    },
    'operator.mira': {
        'role': 'Infrastructure Operator', 'normal_hours': [7, 19],
        'resources': ['/ops/health', '/ops/jobs', '/ops/logs'],
        'actions': ['view_status', 'restart_service', 'read_logs'],
        'devices': ['OPS-WS-04'], 'ips': ['10.0.0.24'], 'usual_permission': 'operator',
        'business_criticality': 'high', 'activity_per_day': 8,
    },
    'admin.jordan': {
        'role': 'Database Administrator', 'normal_hours': [8, 18],
        'resources': ['/db/health', '/db/replicas', '/db/backups'],
        'actions': ['view_status', 'check_replica', 'verify_backup'],
        'devices': ['DB-WS-02'], 'ips': ['10.0.0.31'], 'usual_permission': 'database_admin',
        'business_criticality': 'critical', 'activity_per_day': 5,
    },
}

SENSITIVE_TERMS = ('payroll', 'patient', 'citizen', 'credential', 'secret', 'backup', 'customer', 'restricted', 'production', 'database')
PRIVILEGE_ACTIONS = ('grant_admin', 'add_permission', 'role_change', 'privilege_escalation', 'create_admin')
EXPORT_ACTIONS = ('export', 'download_archive', 'bulk_copy', 'data_export')


def hour_of(value: str) -> int:
    try:
        return datetime.fromisoformat(value.replace('Z', '+00:00')).astimezone(timezone.utc).hour
    except (ValueError, TypeError):
        return 0


def build_baseline(events: list[dict[str, Any]], username: str) -> dict[str, Any]:
    seed = dict(BASELINES.get(username, {}))
    historical = [row for row in events if row['username'] == username and row.get('synthetic_baseline')]
    if historical:
        hours = [hour_of(row['timestamp']) for row in historical]
        resources = Counter(row['resource'] for row in historical)
        actions = Counter(row['action'] for row in historical)
        seed.update({
            'normal_hours': [max(0, min(hours) - 2), min(24, max(hours) + 3)],
            'resources': [key for key, _ in resources.most_common(8)],
            'actions': [key for key, _ in actions.most_common(8)],
            'devices': sorted({row['device'] for row in historical}),
            'ips': sorted({row['source_ip'] for row in historical}),
            'activity_per_day': max(1, round(len(historical) / 7)),
        })
    seed.setdefault('role', 'Standard Administrator')
    seed.setdefault('normal_hours', [8, 18])
    seed.setdefault('resources', [])
    seed.setdefault('actions', [])
    seed.setdefault('devices', [])
    seed.setdefault('ips', [])
    seed.setdefault('usual_permission', 'standard')
    seed.setdefault('business_criticality', 'medium')
    seed.setdefault('activity_per_day', 4)
    return {'username': username, **seed, 'historical_event_count': len(historical)}


def evaluate_event(event: dict[str, Any], baseline: dict[str, Any], maintenance: list[dict[str, Any]], history: list[dict[str, Any]]) -> dict[str, Any]:
    timestamp = datetime.fromisoformat(event['timestamp'].replace('Z', '+00:00')).astimezone(timezone.utc)
    action = event['action'].strip().lower()
    resource = event['resource'].strip().lower()
    resource_sensitive = any(term in resource for term in SENSITIVE_TERMS)
    score = 0
    factors: list[dict[str, Any]] = []

    def add(name: str, points: int, evidence: str) -> None:
        nonlocal score
        score += points
        factors.append({'factor': name, 'points': points, 'evidence': evidence})

    hour_start, hour_end = baseline['normal_hours']
    if not hour_start <= timestamp.hour < hour_end:
        add('Unusual activity time', 15, f'Observed at {timestamp.strftime("%H:%M UTC")}; baseline window is {hour_start:02d}:00–{hour_end:02d}:00 UTC.')
    if event['resource'] not in baseline['resources']:
        add('New resource for this user', 9, f'{event["resource"]} is not among the user’s frequent resources.')
    if event['action'] not in baseline['actions']:
        add('Unusual administrative action', 10, f'{event["action"]} is not among the user’s common actions.')
    if event['device'] not in baseline['devices']:
        add('Unfamiliar device', 12, f'{event["device"]} does not match the user’s common devices.')
    if event['source_ip'] not in baseline['ips']:
        add('Unfamiliar source IP', 10, f'{event["source_ip"]} is not in the user’s common source addresses.')
    if event['permission_level'].lower() not in (baseline['usual_permission'].lower(), 'standard'):
        add('Permission level differs from baseline', 17, f'Observed {event["permission_level"]}; usual level is {baseline["usual_permission"]}.')
    if any(term in action for term in PRIVILEGE_ACTIONS):
        add('Permission change', 24, f'Action {event["action"]} can change account privileges.')
    if event['data_volume_mb'] > 100:
        add('Large data movement', min(24, 12 + int(event['data_volume_mb'] // 1000)), f'{event["data_volume_mb"]:g} MB was accessed or moved.')
    if any(term in action for term in EXPORT_ACTIONS):
        add('Export action', 15, f'{event["action"]} moved data outside the usual read pattern.')
    if resource_sensitive:
        add('Sensitive resource accessed', 11, f'{event["resource"]} appears to contain sensitive or production data.')
    if event.get('login_success') is False or event.get('outcome', '').lower() in ('denied', 'failed', 'failure'):
        add('Unsuccessful access attempt', 8, f'Observed outcome: {event["outcome"]}.')

    related = [row for row in history if row['username'] == event['username'] and row.get('session_id') != event.get('session_id')]
    dates = {row['timestamp'][:10] for row in related}
    deviation_count = len([row for row in related if row.get('deviation_count', 0) > 0])
    if len(dates) >= 2 and deviation_count >= 2:
        add('Gradual deviation across sessions', min(25, 8 + deviation_count * 4), f'{deviation_count + 1} events across {len(dates) + 1} dates differ from the established baseline.')
    same_session = [row for row in history if row['username'] == event['username'] and row.get('session_id') == event.get('session_id')]
    sequence_actions = [row.get('action', '').lower() for row in sorted(same_session, key=lambda row: row.get('timestamp', ''))[-5:]] + [action]
    sequence_has_privilege = any(any(term in previous for term in PRIVILEGE_ACTIONS) for previous in sequence_actions)
    sequence_has_export = any(any(term in previous for term in EXPORT_ACTIONS) for previous in sequence_actions)
    if sequence_has_privilege and sequence_has_export:
        add('Unusual administrative action sequence', 18, 'A permission change and a data export occurred in the same session.')
    sensitive_resources = {row.get('resource') for row in same_session if any(term in str(row.get('resource', '')).lower() for term in SENSITIVE_TERMS)}
    if resource_sensitive and len(sensitive_resources | {event['resource']}) >= 2:
        add('Repeated sensitive resource access', 12, f'{len(sensitive_resources | {event["resource"]})} distinct sensitive resources were used in one session.')

    matching = []
    for window in maintenance:
        start = datetime.fromisoformat(window['starts_at'].replace('Z', '+00:00'))
        end = datetime.fromisoformat(window['ends_at'].replace('Z', '+00:00'))
        inside = start <= timestamp <= end
        same_day = timestamp.date() == start.date()
        user_ok = event['username'] in window['authorized_users']
        action_ok = event['action'] in window['approved_actions']
        resource_ok = event['resource'] in window['approved_resources']
        ref_ok = not event.get('maintenance_ref') or event['maintenance_ref'] == window['change_reference']
        if inside and user_ok and action_ok and resource_ok and ref_ok:
            matching.append(window)
        elif inside or (same_day and user_ok) or event.get('maintenance_ref') == window['change_reference']:
            mismatches = []
            if not inside: mismatches.append('outside the approved time')
            if not user_ok: mismatches.append('user is not authorized')
            if not action_ok: mismatches.append('action is not approved')
            if not resource_ok: mismatches.append('resource is not approved')
            if not ref_ok: mismatches.append('change reference does not match')
            add('Maintenance scope mismatch', 22, f'{window["change_reference"]}: {", ".join(mismatches)}.')
            break
    expected_maintenance = bool(matching)
    if expected_maintenance:
        factors.append({'factor': 'Approved maintenance match', 'points': 0, 'evidence': f'User, action, resource, reference, and schedule match {matching[0]["change_reference"]}.'})

    # A single ordinary action remains a weak signal. Several factors are needed for an alert.
    score = max(0, min(100, score))
    deviation = len([factor for factor in factors if factor['points'] > 0])
    suspicious = (score >= 42 and deviation >= 2) or (score >= 60) or (deviation_count >= 2 and score >= 24)
    # A schedule is only considered matching after exact user/time/action/resource/reference checks.
    # The scope mismatch path above still detects unrelated or over-scoped maintenance activity.
    if expected_maintenance:
        suspicious = False
    level = 'Critical' if score >= 85 else 'High' if score >= 65 else 'Medium' if score >= 40 else 'Low'
    confidence = 'High' if len(event.get('resource', '')) and event.get('device') != 'unknown' and event.get('source_ip') != 'unknown' else 'Medium'
    missing = []
    for key, label in [('device', 'device identity'), ('source_ip', 'source IP')]:
        if not event.get(key) or event[key] == 'unknown': missing.append(label)
    if event['data_volume_mb'] == 0: missing.append('data volume')
    return {
        'suspicious': suspicious, 'expected_maintenance': expected_maintenance,
        'risk_score': score, 'risk_level': level, 'confidence': confidence,
        'missing_evidence': missing, 'factors': factors,
        'deviation_count': deviation_count + int(deviation > 0),
        'sensitive_resource': resource_sensitive,
    }
