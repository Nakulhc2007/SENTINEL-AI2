from __future__ import annotations

import json
import os
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

DATABASE_PATH = Path(os.getenv('PORTAL_DATABASE_PATH', Path(__file__).resolve().parents[1] / 'portal.sqlite3'))


@contextmanager
def connect():
    connection = sqlite3.connect(DATABASE_PATH, timeout=10)
    connection.row_factory = sqlite3.Row
    connection.execute('PRAGMA foreign_keys = ON')
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def initialize() -> None:
    DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)
    with connect() as connection:
        connection.executescript('''
            CREATE TABLE IF NOT EXISTS lotl_events (
                event_id TEXT PRIMARY KEY, timestamp TEXT NOT NULL, username TEXT NOT NULL,
                organization_domain TEXT NOT NULL DEFAULT 'corporate',
                session_id TEXT NOT NULL, synthetic_baseline INTEGER NOT NULL DEFAULT 0,
                event_json TEXT NOT NULL, run_id TEXT
            );
            CREATE INDEX IF NOT EXISTS lotl_events_user_time ON lotl_events(username,timestamp DESC);
            CREATE TABLE IF NOT EXISTS lotl_maintenance (
                maintenance_id TEXT PRIMARY KEY, organization_domain TEXT NOT NULL DEFAULT 'corporate',
                starts_at TEXT NOT NULL, ends_at TEXT NOT NULL,
                authorized_users_json TEXT NOT NULL, approved_actions_json TEXT NOT NULL,
                approved_resources_json TEXT NOT NULL, description TEXT NOT NULL,
                change_reference TEXT NOT NULL, status TEXT NOT NULL, created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS lotl_runs (
                run_id TEXT PRIMARY KEY, scenario_id TEXT NOT NULL, organization_domain TEXT NOT NULL DEFAULT 'corporate', name TEXT NOT NULL,
                created_at TEXT NOT NULL, outcome TEXT NOT NULL, result_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS lotl_incidents (
                incident_id TEXT PRIMARY KEY, run_id TEXT NOT NULL, organization_domain TEXT NOT NULL DEFAULT 'corporate', username TEXT NOT NULL,
                created_at TEXT NOT NULL, risk_score INTEGER NOT NULL, risk_level TEXT NOT NULL,
                status TEXT NOT NULL, incident_json TEXT NOT NULL, decision_json TEXT
            );
            CREATE INDEX IF NOT EXISTS lotl_incidents_status ON lotl_incidents(status,created_at DESC);
            CREATE TABLE IF NOT EXISTS lotl_audit (
                audit_id TEXT PRIMARY KEY, run_id TEXT, incident_id TEXT, actor TEXT NOT NULL,
                action TEXT NOT NULL, details TEXT NOT NULL, created_at TEXT NOT NULL,
                organization_domain TEXT
            );
        ''')
        audit_columns = {row['name'] for row in connection.execute('PRAGMA table_info(lotl_audit)').fetchall()}
        if 'organization_domain' not in audit_columns:
            connection.execute('ALTER TABLE lotl_audit ADD COLUMN organization_domain TEXT')
        now = datetime.now(timezone.utc).replace(microsecond=0)
        for domain in ('banking', 'healthcare', 'education', 'government', 'corporate', 'manufacturing', 'retail', 'public-services'):
            count = connection.execute('SELECT COUNT(*) FROM lotl_events WHERE synthetic_baseline=1 AND organization_domain=?', (domain,)).fetchone()[0]
            if count == 0:
              for username, profile in _baseline_profiles().items():
                for day in range(1, 8):
                    for position, action in enumerate(profile['actions']):
                        stamp = (now - timedelta(days=day)).replace(hour=profile['hour'], minute=8 + position * 9)
                        event = {'event_id': f'BASE-{domain}-{username}-{day}-{position}', 'timestamp': stamp.isoformat(timespec='seconds'), 'username': username, 'organization_domain': domain, 'user_role': profile['role'], 'source_ip': profile['ip'], 'device': profile['device'], 'login_success': True, 'process_category': 'Administrative console', 'action': action, 'resource': profile['resources'][position % len(profile['resources'])], 'permission_level': profile['permission'], 'data_volume_mb': 0, 'maintenance_ref': None, 'outcome': 'success', 'business_criticality': profile['criticality'], 'session_id': f'baseline-{domain}-{username}-{day}', 'synthetic_baseline': True}
                        connection.execute('INSERT OR IGNORE INTO lotl_events(event_id,timestamp,username,organization_domain,session_id,synthetic_baseline,event_json) VALUES(?,?,?,?,?,?,?)', (event['event_id'], event['timestamp'], username, domain, event['session_id'], 1, json.dumps(event)))


def _baseline_profiles() -> dict[str, dict[str, Any]]:
    return {
        'admin.alex': {'role': 'Systems Administrator', 'hour': 10, 'actions': ['view_status', 'restart_service', 'rotate_logs'], 'resources': ['/admin/health', '/admin/jobs', '/admin/users'], 'ip': '10.0.0.10', 'device': 'ADM-WS-01', 'permission': 'administrator', 'criticality': 'high'},
        'operator.mira': {'role': 'Infrastructure Operator', 'hour': 11, 'actions': ['view_status', 'restart_service', 'read_logs'], 'resources': ['/ops/health', '/ops/jobs', '/ops/logs'], 'ip': '10.0.0.24', 'device': 'OPS-WS-04', 'permission': 'operator', 'criticality': 'high'},
        'admin.jordan': {'role': 'Database Administrator', 'hour': 9, 'actions': ['view_status', 'check_replica', 'verify_backup'], 'resources': ['/db/health', '/db/replicas', '/db/backups'], 'ip': '10.0.0.31', 'device': 'DB-WS-02', 'permission': 'database_admin', 'criticality': 'critical'},
    }


def rows(sql: str, args: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
    with connect() as connection:
        return [dict(row) for row in connection.execute(sql, args).fetchall()]


def json_rows(sql: str, key: str, args: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
    result = []
    for row in rows(sql, args):
        result.append({**row, key: json.loads(row.pop(f'{key}_json'))})
    return result


def new_id(prefix: str) -> str:
    return f'{prefix}-{uuid.uuid4().hex[:10].upper()}'


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat(timespec='seconds')
