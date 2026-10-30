from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
from typing import Any

from .schemas import ActivityEvent


def _at(day: datetime, hour: int, minute: int = 0) -> str:
    return day.replace(hour=hour, minute=minute, second=0, microsecond=0).astimezone(timezone.utc).isoformat(timespec='seconds')


def _event_models(scenario_id: str, domain: str, rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    output = []
    for row in rows:
        if not row.get('event_id'):
            identity = '|'.join((domain, scenario_id, str(row.get('timestamp')), str(row.get('username')), str(row.get('action')), str(row.get('resource'))))
            row['event_id'] = f'DEMO-{hashlib.sha256(identity.encode()).hexdigest()[:16].upper()}'
        output.append(ActivityEvent(organization_domain=domain, **row).model_dump(mode='json'))
    return output


def scenario_bundle(scenario_id: str, now: datetime | None = None, organization_domain: str = 'corporate') -> dict[str, Any]:
    now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    today = now.replace(hour=10, minute=0, second=0, microsecond=0)
    yesterday = today - timedelta(days=1)
    user = 'admin.alex'
    base = {'username': user, 'user_role': 'Systems Administrator', 'source_ip': '10.0.0.10', 'device': 'ADM-WS-01', 'process_category': 'PowerShell', 'permission_level': 'administrator', 'business_criticality': 'high'}
    if scenario_id == 'normal-administration':
        rows = [
            base | {'timestamp': _at(today, 10, 5), 'action': 'view_status', 'resource': '/admin/health', 'outcome': 'success'},
            base | {'timestamp': _at(today, 10, 8), 'action': 'restart_service', 'resource': '/admin/jobs', 'maintenance_ref': 'CHG-NORMAL-01', 'outcome': 'success'},
        ]
        maintenance = [_window(today, 9, 0, 12, 0, user, ['view_status', 'restart_service'], ['/admin/health', '/admin/jobs'], 'CHG-NORMAL-01', 'Routine service health check')]
        return {'id': scenario_id, 'name': 'Normal administration', 'description': 'Routine administrator work during regular hours with familiar device, resources, and an approved small change.', 'events': _event_models(scenario_id, organization_domain, rows), 'maintenance': maintenance}
    if scenario_id == 'suspicious-night-activity':
        night = today.replace(hour=2, minute=10)
        rows = [
            base | {'timestamp': _at(night, 2, 10), 'source_ip': '203.0.113.77', 'device': 'UNKNOWN-LINUX-8', 'action': 'grant_admin', 'process_category': 'document_management', 'resource': '/production/payroll.xlsx', 'permission_level': 'global_admin', 'data_volume_mb': 780, 'outcome': 'success', 'session_id': 'night-session-1'},
            base | {'timestamp': _at(night, 2, 16), 'source_ip': '203.0.113.77', 'device': 'UNKNOWN-LINUX-8', 'action': 'data_export', 'process_category': 'document_management', 'resource': '/production/customer-backup.csv', 'permission_level': 'global_admin', 'data_volume_mb': 640, 'outcome': 'success', 'session_id': 'night-session-1'},
        ]
        return {'id': scenario_id, 'name': 'Suspicious night activity', 'description': 'Sensitive production exports and a permission change at 02:10 from a new device, outside an approved maintenance window.', 'events': _event_models(scenario_id, organization_domain, rows), 'maintenance': []}
    if scenario_id == 'gradual-credential-misuse':
        rows = []
        for days, hour, action, resource in [
            (3, 20, 'read_logs', '/ops/credential-vault'),
            (2, 21, 'check_replica', '/ops/customer-backup'),
            (1, 22, 'read_logs', '/ops/production-secrets'),
            (0, 23, 'data_export', '/ops/customer-backup'),
        ]:
            stamp = (now - timedelta(days=days)).replace(hour=hour, minute=12, second=0, microsecond=0)
            rows.append({'timestamp': stamp.isoformat(timespec='seconds'), 'username': 'operator.mira', 'user_role': 'Infrastructure Operator', 'source_ip': '10.0.0.24' if days else '198.51.100.92', 'device': 'OPS-WS-04' if days > 1 else 'NEW-DEVICE-51', 'process_category': 'Administrative shell', 'action': action, 'resource': resource, 'permission_level': 'operator', 'data_volume_mb': 180 if days == 0 else 0, 'outcome': 'success', 'session_id': f'grad-session-{days}', 'business_criticality': 'high'})
        return {'id': scenario_id, 'name': 'Gradual credential misuse', 'description': 'Small deviations accumulate across separate sessions and days, followed by an unusual export from a new device.', 'events': _event_models(scenario_id, organization_domain, rows), 'maintenance': []}
    if scenario_id == 'approved-maintenance':
        begin = now - timedelta(minutes=30)
        finish = now + timedelta(minutes=30)
        maint_user = 'admin.jordan'
        rows = [
            {'timestamp': now.replace(second=0, microsecond=0).isoformat(timespec='seconds'), 'username': maint_user, 'user_role': 'Database Administrator', 'source_ip': '10.0.0.31', 'device': 'DB-WS-02', 'process_category': 'Database console', 'permission_level': 'database_admin', 'business_criticality': 'critical', 'action': 'check_replica', 'resource': '/db/replicas', 'maintenance_ref': 'CHG-APPROVED-42', 'outcome': 'success', 'session_id': 'approved-maintenance-42'},
            {'timestamp': (now + timedelta(minutes=3)).replace(second=0, microsecond=0).isoformat(timespec='seconds'), 'username': maint_user, 'user_role': 'Database Administrator', 'source_ip': '10.0.0.31', 'device': 'DB-WS-02', 'process_category': 'Database console', 'permission_level': 'database_admin', 'business_criticality': 'critical', 'action': 'verify_backup', 'resource': '/db/backups', 'maintenance_ref': 'CHG-APPROVED-42', 'outcome': 'success', 'session_id': 'approved-maintenance-42'},
        ]
        window = {'maintenance_id': 'MAINT-APPROVED-42', 'starts_at': begin.isoformat(timespec='seconds'), 'ends_at': finish.isoformat(timespec='seconds'), 'authorized_users': [maint_user], 'approved_actions': ['check_replica', 'verify_backup'], 'approved_resources': ['/db/replicas', '/db/backups'], 'description': 'Approved synthetic database maintenance window for the scenario demonstration.', 'change_reference': 'CHG-APPROVED-42', 'status': 'approved'}
        window['organization_domain'] = organization_domain
        return {'id': scenario_id, 'name': 'Approved maintenance', 'description': 'Sensitive administration within an approved schedule. Actions, resources, user, and reference are still checked.', 'events': _event_models(scenario_id, organization_domain, rows), 'maintenance': [window]}
    raise KeyError(scenario_id)


def _window(day: datetime, start_hour: int, start_minute: int, end_hour: int, end_minute: int, user: str, actions: list[str], resources: list[str], reference: str, description: str) -> dict[str, Any]:
    return {'maintenance_id': reference, 'starts_at': _at(day, start_hour, start_minute), 'ends_at': _at(day, end_hour, end_minute), 'authorized_users': [user], 'approved_actions': actions, 'approved_resources': resources, 'description': description, 'change_reference': reference, 'status': 'approved'}
