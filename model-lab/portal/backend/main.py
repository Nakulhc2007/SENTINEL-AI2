from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import time
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import httpx
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from lotl.router import router as lotl_router
from lotl.storage import initialize as initialize_lotl_database

HERE = Path(__file__).resolve().parent
PORTAL_ROOT = HERE.parent
MODEL_PATH = PORTAL_ROOT.parent / 'artifacts' / 'model.json'
DATABASE_PATH = Path(os.getenv('PORTAL_DATABASE_PATH', HERE / 'portal.sqlite3'))
SENTINEL_API_URL = os.getenv('SENTINEL_API_URL', 'http://127.0.0.1:8000/api/sentinel/events/batch').strip()
SENTINEL_API_KEY = os.getenv('SENTINEL_API_KEY', '').strip()
DEMO_PASSWORD = os.getenv('DEMO_ACCOUNT_PASSWORD', 'ServiceDemo-2026!')
FILE_ACCESS_CODES = {
    1001: 'FILE-A7KQ-29',
    1002: 'FILE-M4PD-81',
    1003: 'FILE-R9TX-36',
    1004: 'FILE-C2WN-57',
}
COOKIE_NAME = 'civicshield_session'
COOKIE_SECURE = os.getenv('COOKIE_SECURE', 'false').lower() == 'true'
SESSION_HOURS = 8
DOMAINS = {
    'business-services': {'name': 'Business Services Portal', 'abbr': 'SMB', 'org': 'CivicShield Business Services'},
    'banking': {'name': 'Banking Services Portal', 'abbr': 'BNK', 'org': 'CivicShield Banking Services'},
    'healthcare': {'name': 'Healthcare Services Portal', 'abbr': 'HLT', 'org': 'CivicShield Health Services'},
    'education': {'name': 'Education & Scholarship Portal', 'abbr': 'EDU', 'org': 'CivicShield Education Services'},
    'ecommerce': {'name': 'E-commerce Services Portal', 'abbr': 'SHOP', 'org': 'CivicShield Commerce Services'},
    'cybersecurity': {'name': 'Cybersecurity Operations Portal', 'abbr': 'CYBER', 'org': 'CivicShield Security Operations'},
    'government': {'name': 'Government Citizen Services Portal', 'abbr': 'CIT', 'org': 'CivicShield Citizen Services'},
    'it-administration': {'name': 'IT Administration Portal', 'abbr': 'IT', 'org': 'CivicShield IT Administration'},
}
MODEL_DOMAIN = {
    'business-services': 'corporate', 'banking': 'banking', 'healthcare': 'healthcare',
    'education': 'education', 'ecommerce': 'retail', 'cybersecurity': 'corporate',
    'government': 'government', 'it-administration': 'public_services',
}
TRAINED_DOMAIN_NAMES = {
    'banking': 'Banking', 'healthcare': 'Healthcare', 'education': 'Education',
    'government': 'Government', 'corporate': 'Corporate', 'manufacturing': 'Manufacturing',
    'retail': 'Retail', 'public_services': 'Public Services',
}
DEMO_USER_PREFIXES = {
    'business-services': 'business', 'banking': 'bank', 'healthcare': 'health',
    'education': 'education', 'ecommerce': 'shop', 'cybersecurity': 'cyber',
    'government': 'citizen', 'it-administration': 'it',
}
DEMO_CUSTOMERS = {
    'business-services': ('Aarav Mehta', 'Diya Shah', 'Rohan Iyer', 'Mira Das'),
    'banking': ('Aarav Mehta', 'Diya Shah', 'Rohan Iyer', 'Mira Das'),
    'healthcare': ('Anaya Rao', 'Kabir Nair', 'Sara Khan', 'Ishaan Patel'),
    'education': ('Anaya Rao', 'Kabir Nair', 'Sara Khan', 'Ishaan Patel'),
    'ecommerce': ('Aarav Mehta', 'Diya Shah', 'Rohan Iyer', 'Mira Das'),
    'cybersecurity': ('Aarav Mehta', 'Diya Shah', 'Sara Khan', 'Ishaan Patel'),
    'government': ('Aarav Mehta', 'Diya Shah', 'Rohan Iyer', 'Mira Das'),
    'it-administration': ('Aarav Mehta', 'Diya Shah', 'Sara Khan', 'Ishaan Patel'),
}
DEPRECATED_DEMO_USERS = (
    'demo_business', 'demo_bank', 'demo_health', 'demo_education', 'demo_shop',
    'demo_cyber', 'demo_citizen', 'demo_it',
)
DEMO_USERS = [
    (f"{DEMO_USER_PREFIXES[domain]}_user_{1000 + index}", name, domain)
    for domain, names in DEMO_CUSTOMERS.items()
    for index, name in enumerate(names, start=1)
]
SAMPLE_PROFILES = {
    'business-services': [
        ('DEMO-BIZ-1001', 'Pune', 'Active', 'Business', 'Mehta Craft Foods', 'Service request', 'Small business registration', 'Next step', 'Document review · 12 Nov'),
        ('DEMO-BIZ-1002', 'Surat', 'In review', 'Business', 'Sunrise Textiles', 'Service request', 'Trade permit renewal', 'Next step', 'Upload sample form'),
        ('DEMO-BIZ-1003', 'Chennai', 'Active', 'Business', 'Harbor Design Studio', 'Service request', 'Business profile update', 'Next step', 'No action required'),
        ('DEMO-BIZ-1004', 'Kolkata', 'Completed', 'Business', 'Greenway Supplies', 'Service request', 'Vendor registration', 'Next step', 'View confirmation'),
    ],
    'banking': [
        ('DEMO-BNK-1001', 'Pune', 'Active', 'Account type', 'Everyday savings', 'Last transaction', 'Sample grocery payment · ₹2,450', 'Branch', 'Pune Central · Demo Branch', '₹84,250.75'),
        ('DEMO-BNK-1002', 'Surat', 'Active', 'Account type', 'Current account', 'Last transaction', 'Sample supplier payment · ₹8,200', 'Branch', 'Surat Market · Demo Branch', '₹2,36,800.00'),
        ('DEMO-BNK-1003', 'Chennai', 'Active', 'Account type', 'Everyday savings', 'Last transaction', 'Sample utility bill · ₹1,180', 'Branch', 'Chennai Marina · Demo Branch', '₹56,420.50'),
        ('DEMO-BNK-1004', 'Kolkata', 'Active', 'Account type', 'Student savings', 'Last transaction', 'Sample transport payment · ₹640', 'Branch', 'Kolkata North · Demo Branch', '₹18,905.25'),
    ],
    'healthcare': [
        ('DEMO-HLT-1001', 'Hyderabad', 'Appointment booked', 'Care service', 'General health check', 'Next appointment', '18 Nov · 10:30 AM', 'Clinic', 'CivicShield Demo Clinic'),
        ('DEMO-HLT-1002', 'Kochi', 'Follow-up due', 'Care service', 'Routine follow-up', 'Next appointment', '21 Nov · 2:00 PM', 'Clinic', 'CivicShield Demo Clinic'),
        ('DEMO-HLT-1003', 'Jaipur', 'Completed', 'Care service', 'Annual wellness visit', 'Visit summary', 'Sample summary available', 'Clinic', 'CivicShield Demo Clinic'),
        ('DEMO-HLT-1004', 'Ahmedabad', 'Appointment booked', 'Care service', 'Nutrition consultation', 'Next appointment', '25 Nov · 11:15 AM', 'Clinic', 'CivicShield Demo Clinic'),
    ],
    'education': [
        ('DEMO-EDU-1001', 'Hyderabad', 'Enrolled', 'Course', 'Information Systems · Year 2', 'Scholarship', 'Merit grant · approved', 'Next term', 'Starts 2 Dec'),
        ('DEMO-EDU-1002', 'Kochi', 'Application received', 'Course', 'Business Studies · Year 1', 'Scholarship', 'Application under review', 'Next step', 'Decision due 20 Nov'),
        ('DEMO-EDU-1003', 'Jaipur', 'Enrolled', 'Course', 'Public Health · Year 3', 'Scholarship', 'Community grant · approved', 'Next term', 'Starts 2 Dec'),
        ('DEMO-EDU-1004', 'Ahmedabad', 'Documents needed', 'Course', 'Engineering · Year 1', 'Scholarship', 'Supporting form requested', 'Due date', '22 Nov'),
    ],
    'ecommerce': [
        ('DEMO-SHP-1001', 'Pune', 'On the way', 'Recent order', 'DEMO-ORD-5401 · Home supplies', 'Estimated delivery', '16 Nov', 'Reward points', '240 sample points'),
        ('DEMO-SHP-1002', 'Surat', 'Order confirmed', 'Recent order', 'DEMO-ORD-5402 · Clothing', 'Estimated delivery', '18 Nov', 'Reward points', '510 sample points'),
        ('DEMO-SHP-1003', 'Chennai', 'Delivered', 'Recent order', 'DEMO-ORD-5403 · Books', 'Delivered on', '10 Nov', 'Reward points', '125 sample points'),
        ('DEMO-SHP-1004', 'Kolkata', 'Ready for pickup', 'Recent order', 'DEMO-ORD-5404 · Electronics', 'Pickup location', 'CivicShield Demo Store', 'Reward points', '390 sample points'),
    ],
    'cybersecurity': [
        ('DEMO-CYB-1001', 'Pune', 'In progress', 'Learning plan', 'Digital safety basics', 'Completion', '3 of 5 modules', 'Certificate', 'Available after completion'),
        ('DEMO-CYB-1002', 'Surat', 'Completed', 'Learning plan', 'Online account safety', 'Completion', '5 of 5 modules', 'Certificate', 'Sample certificate ready'),
        ('DEMO-CYB-1003', 'Jaipur', 'Enrolled', 'Learning plan', 'Privacy awareness', 'Completion', '1 of 4 modules', 'Next class', '19 Nov · Online'),
        ('DEMO-CYB-1004', 'Ahmedabad', 'Completed', 'Learning plan', 'Safe device use', 'Completion', '4 of 4 modules', 'Certificate', 'Sample certificate ready'),
    ],
    'government': [
        ('DEMO-CIT-1001', 'Pune', 'In progress', 'Service request', 'Address update', 'Application', 'DEMO-APP-2301', 'Next step', 'Review sample form'),
        ('DEMO-CIT-1002', 'Surat', 'Completed', 'Service request', 'Community certificate', 'Application', 'DEMO-APP-2302', 'Completed', '8 Nov'),
        ('DEMO-CIT-1003', 'Chennai', 'Appointment booked', 'Service request', 'Resident services visit', 'Appointment', '22 Nov · 9:30 AM', 'Location', 'CivicShield Demo Office'),
        ('DEMO-CIT-1004', 'Kolkata', 'In review', 'Service request', 'Public library membership', 'Application', 'DEMO-APP-2304', 'Next step', 'Awaiting sample review'),
    ],
    'it-administration': [
        ('DEMO-IT-1001', 'Pune', 'Being prepared', 'Equipment', 'Laptop · DEMO-ASSET-801', 'Service request', 'New starter setup', 'Collection', '18 Nov · Demo IT Desk'),
        ('DEMO-IT-1002', 'Surat', 'In progress', 'Equipment', 'Monitor · DEMO-ASSET-802', 'Service request', 'Display replacement', 'Update', 'Technician assigned'),
        ('DEMO-IT-1003', 'Jaipur', 'Resolved', 'Equipment', 'Laptop · DEMO-ASSET-803', 'Service request', 'Software setup', 'Completed', '11 Nov'),
        ('DEMO-IT-1004', 'Ahmedabad', 'Received', 'Equipment', 'Tablet · DEMO-ASSET-804', 'Service request', 'Device support', 'Next update', 'Expected 17 Nov'),
    ],
}
FEATURE_NAMES = [
    'failed_logins', 'success_after_failures', 'unfamiliar_region', 'after_hours',
    'restricted_access_attempts', 'request_rate_ratio', 'malware_alerts',
    'document_hash_mismatch', 'sensitive_resource_access', 'privilege_changes',
    'unique_source_ips', 'source_reputation', 'managed_device', 'events_in_5m',
]
DOMAIN_FEATURES = ['banking', 'healthcare', 'education', 'government', 'corporate', 'manufacturing', 'retail', 'public_services']
model_data: dict[str, Any] = json.loads(MODEL_PATH.read_text(encoding='utf-8')) if MODEL_PATH.exists() else {}
login_attempts: dict[str, list[float]] = {}
captcha_challenges: dict[str, tuple[str, float]] = {}


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec='seconds')


def db() -> sqlite3.Connection:
    connection = sqlite3.connect(DATABASE_PATH, timeout=10)
    connection.row_factory = sqlite3.Row
    connection.execute('PRAGMA foreign_keys = ON')
    return connection


def init_db() -> None:
    DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)
    with db() as connection:
        connection.executescript('''
            PRAGMA journal_mode = WAL;
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY, display_name TEXT NOT NULL, domain TEXT NOT NULL,
                password_hash TEXT NOT NULL, created_at TEXT NOT NULL,
                must_change_password INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS sessions (
                token_hash TEXT PRIMARY KEY, username TEXT NOT NULL REFERENCES users(username) ON DELETE CASCADE,
                expires_at TEXT NOT NULL, created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS events (
                event_id TEXT PRIMARY KEY, timestamp TEXT NOT NULL, organization_domain TEXT NOT NULL,
                username TEXT NOT NULL, source_ip TEXT NOT NULL, event_type TEXT NOT NULL,
                resource TEXT NOT NULL, severity TEXT NOT NULL, details TEXT NOT NULL,
                metadata_json TEXT NOT NULL DEFAULT '{}', delivery_status TEXT NOT NULL DEFAULT 'pending',
                attempts INTEGER NOT NULL DEFAULT 0, last_attempt_at TEXT, last_error TEXT,
                sentinel_result TEXT, created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS events_domain_time ON events(organization_domain, timestamp DESC);
            CREATE INDEX IF NOT EXISTS events_user_type_time ON events(username, event_type, timestamp DESC);
            CREATE TABLE IF NOT EXISTS alerts (
                alert_id TEXT PRIMARY KEY, event_id TEXT NOT NULL UNIQUE, organization_domain TEXT NOT NULL,
                organization_name TEXT NOT NULL, username TEXT NOT NULL, event_type TEXT NOT NULL,
                source_ip TEXT NOT NULL, timestamp TEXT NOT NULL, risk_score INTEGER NOT NULL,
                risk_level TEXT NOT NULL, incident_status TEXT NOT NULL, summary TEXT NOT NULL,
                agents_json TEXT NOT NULL, created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS private_documents (
                username TEXT PRIMARY KEY REFERENCES users(username) ON DELETE CASCADE,
                filename TEXT NOT NULL, reference_sha256 TEXT NOT NULL, created_at TEXT NOT NULL
            );
        ''')
        user_columns = {row['name'] for row in connection.execute('PRAGMA table_info(users)').fetchall()}
        if 'must_change_password' not in user_columns:
            connection.execute('ALTER TABLE users ADD COLUMN must_change_password INTEGER NOT NULL DEFAULT 0')
        connection.execute("DELETE FROM users WHERE username LIKE '%-ADM-%' COLLATE NOCASE OR username IN (" + ','.join('?' for _ in DEPRECATED_DEMO_USERS) + ')', DEPRECATED_DEMO_USERS)
        for username, display_name, domain in DEMO_USERS:
            connection.execute(
                'INSERT OR IGNORE INTO users(username, display_name, domain, password_hash, created_at) VALUES(?,?,?,?,?)',
                (username, display_name, domain, hash_password(DEMO_PASSWORD), now_iso()),
            )
    ensure_private_documents()


DOCUMENT_FILENAMES = {
    'business-services': 'business-service-record.txt', 'banking': 'sample-bank-statement.txt',
    'healthcare': 'sample-care-summary.txt', 'education': 'student-service-record.txt',
    'ecommerce': 'sample-order-receipt.txt', 'cybersecurity': 'awareness-course-record.txt',
    'government': 'citizen-service-record.txt', 'it-administration': 'it-service-request.txt',
}


def ensure_private_documents() -> None:
    private_root = HERE / 'private_files'
    private_root.mkdir(parents=True, exist_ok=True)
    for username, name, domain in DEMO_USERS:
        index = int(username.rsplit('_', 1)[1]) - 1001
        profile = SAMPLE_PROFILES[domain][index]
        reference, city, status, kind_label, kind, detail_label, detail, extra_label, extra = profile[:9]
        lines = [
            'CIVICSHIELD FICTIONAL DEMONSTRATION RECORD',
            'All content below is synthetic sample data, not a real personal, medical, financial, or government record.',
            '', f'Service: {DOMAINS[domain]["name"]}', f'Name: {name}', f'City: {city}',
            f'Reference: {reference}', f'Status: {status}', f'{kind_label}: {kind}',
            f'{detail_label}: {detail}', f'{extra_label}: {extra}',
        ]
        if domain == 'banking':
            lines.append(f'Sample balance: {profile[9]}')
        filename = DOCUMENT_FILENAMES[domain]
        path = private_root / f'{username}-{filename}'
        if not path.exists():
            path.write_text('\n'.join(lines) + '\n', encoding='utf-8')
        current_hash = hashlib.sha256(path.read_bytes()).hexdigest()
        with db() as connection:
            connection.execute('''INSERT OR IGNORE INTO private_documents(username,filename,reference_sha256,created_at)
                VALUES(?,?,?,?)''', (username, path.name, current_hash, now_iso()))


def document_integrity(username: str) -> dict[str, str]:
    with db() as connection:
        row = connection.execute('SELECT filename,reference_sha256 FROM private_documents WHERE username=?', (username,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail='No private sample document is assigned to this account.')
    path = HERE / 'private_files' / row['filename']
    if not path.is_file():
        raise HTTPException(status_code=404, detail='The private sample document is unavailable.')
    current_hash = hashlib.sha256(path.read_bytes()).hexdigest()
    return {'filename': row['filename'], 'reference_sha256': row['reference_sha256'],
            'current_sha256': current_hash, 'status': 'Verified' if hmac.compare_digest(current_hash, row['reference_sha256']) else 'Modified'}


def hash_password(password: str, salt: bytes | None = None) -> str:
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode('utf-8'), salt=salt, n=2**14, r=8, p=1, dklen=64)
    return f'scrypt${salt.hex()}${digest.hex()}'


def verify_password(password: str, encoded: str) -> bool:
    try:
        algorithm, salt_hex, expected = encoded.split('$', 2)
        if algorithm != 'scrypt':
            return False
        actual = hashlib.scrypt(password.encode('utf-8'), salt=bytes.fromhex(salt_hex), n=2**14, r=8, p=1, dklen=64).hex()
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError):
        return False


def client_ip(request: Request) -> str:
    return request.client.host if request.client else 'unknown'


def event_dict(row: sqlite3.Row) -> dict[str, Any]:
    return {
        'event_id': row['event_id'], 'timestamp': row['timestamp'],
        'organization_domain': row['organization_domain'], 'username': row['username'],
        'source_ip': row['source_ip'], 'event_type': row['event_type'], 'resource': row['resource'],
        'severity': row['severity'], 'details': row['details'],
        'delivery_status': row['delivery_status'], 'attempts': row['attempts'],
        'last_error': row['last_error'],
    }


def record_event(domain: str, username: str, source_ip: str, event_type: str, resource: str,
                 severity: str, details: str, metadata: dict[str, Any] | None = None) -> dict[str, Any]:
    if domain not in DOMAINS:
        raise ValueError('Unknown organization domain')
    event_id = secrets.token_hex(12)
    timestamp = now_iso()
    metadata_json = json.dumps(metadata or {}, separators=(',', ':'))
    with db() as connection:
        connection.execute('''INSERT INTO events(
            event_id,timestamp,organization_domain,username,source_ip,event_type,resource,severity,
            details,metadata_json,delivery_status,created_at
        ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)''', (
            event_id, timestamp, domain, username, source_ip, event_type, resource,
            severity, details, metadata_json, 'pending' if SENTINEL_API_URL else 'not_configured', timestamp,
        ))
        row = connection.execute('SELECT * FROM events WHERE event_id=?', (event_id,)).fetchone()
        return event_dict(row) | {'metadata': metadata or {}}


def get_session_user(request: Request) -> sqlite3.Row | None:
    raw_token = request.cookies.get(COOKIE_NAME)
    if not raw_token:
        return None
    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
    with db() as connection:
        row = connection.execute('''SELECT users.* FROM sessions JOIN users USING(username)
            WHERE sessions.token_hash=? AND sessions.expires_at>?''', (token_hash, now_iso())).fetchone()
    return row


def require_user(request: Request, allow_password_reset: bool = False) -> sqlite3.Row:
    user = get_session_user(request)
    if not user:
        raise HTTPException(status_code=401, detail='Please sign in to this service portal.')
    if user['must_change_password'] and not allow_password_reset:
        raise HTTPException(status_code=403, detail='Change your password to continue.')
    return user


def recent_activity(username: str, domain: str) -> list[sqlite3.Row]:
    since = (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat(timespec='seconds')
    with db() as connection:
        return connection.execute('''SELECT * FROM events WHERE username=? AND organization_domain=?
            AND timestamp>=? ORDER BY timestamp DESC''', (username, domain, since)).fetchall()


def make_model_vector(event: dict[str, Any], prior: list[sqlite3.Row]) -> list[float]:
    event_type = event['event_type']
    metadata = event.get('metadata') or {}
    failed_types = ('login_failed', 'captcha_failed', 'login_failed_simulated')
    failed = sum(1 for row in prior if row['event_type'] in failed_types)
    if event_type in failed_types:
        failed += 1
    unique_ips = len({row['source_ip'] for row in prior} | {event['source_ip']})
    feature_values = {
        'failed_logins': failed,
        'success_after_failures': int(event_type == 'login_success' and failed >= 5),
        'unfamiliar_region': int(event_type == 'suspicious_login_simulated'),
        'after_hours': int(datetime.now().hour < 7 or datetime.now().hour >= 21),
        'restricted_access_attempts': int(event_type == 'unauthorized_access_simulated'),
        'request_rate_ratio': 8.0 if event_type == 'high_request_volume_simulated' else 1.0,
        'malware_alerts': 0,
        'document_hash_mismatch': int(event_type == 'document_modification_simulated'),
        'sensitive_resource_access': int(event_type in ('unauthorized_access_simulated', 'document_modification_simulated')),
        'privilege_changes': 0,
        'unique_source_ips': unique_ips,
        'source_reputation': 18 if event_type in ('suspicious_login_simulated', 'unauthorized_access_simulated') else 86,
        'managed_device': int(event_type not in ('suspicious_login_simulated', 'unauthorized_access_simulated')),
        'events_in_5m': len(prior) + 1,
    }
    model_domain = MODEL_DOMAIN[event['organization_domain']]
    ordered = [feature_values[name] for name in FEATURE_NAMES]
    ordered.extend(1 if model_domain == candidate else 0 for candidate in DOMAIN_FEATURES)
    return ordered


def model_probability(event: dict[str, Any], prior: list[sqlite3.Row]) -> float:
    if not model_data.get('trees'):
        return 0.0
    vector = make_model_vector(event, prior)
    scores = []
    for tree in model_data['trees']:
        node = tree
        while 'left' in node and 'right' in node:
            node = node['left'] if vector[node['f']] <= node['t'] else node['right']
        scores.append(float(node['p']))
    return sum(scores) / len(scores)


def analyze_event(event: dict[str, Any], prior: list[sqlite3.Row]) -> dict[str, Any] | None:
    event_type = event['event_type']
    if event_type == 'password_change_required':
        return None
    failed_types = ('login_failed', 'captcha_failed', 'login_failed_simulated')
    failed_rows = [row for row in prior if row['event_type'] in failed_types]
    failed_count = len(failed_rows) + int(event_type in failed_types)
    is_failed_signin = event_type in ('login_failed', 'captcha_failed')
    if is_failed_signin and failed_count < 3:
        return None

    metadata = event.get('metadata') or {}
    probability = model_probability(event, prior)
    rules = {
        'unusual_login': is_failed_signin and failed_count >= 3,
        'repeated_failed_login': failed_count >= 5 and event_type in ('login_failed', 'login_failed_simulated', 'login_success'),
        'unauthorized_access': event_type == 'unauthorized_access_simulated',
        'suspicious_login': event_type == 'suspicious_login_simulated',
        'high_request_volume': event_type == 'high_request_volume_simulated',
        'document_modification': event_type == 'document_modification_simulated',
    }
    matched = [name for name, active in rules.items() if active]
    if not matched and probability < 0.5:
        return None

    failure_reasons = []
    for row in failed_rows:
        try:
            failure_reasons.append(json.loads(row['metadata_json'] or '{}').get('failure_reason', 'password'))
        except (TypeError, json.JSONDecodeError):
            failure_reasons.append('password')
    if is_failed_signin:
        failure_reasons.append(metadata.get('failure_reason', 'password'))
    failure_reasons = [reason for reason in failure_reasons if reason]
    reason_labels = {'password': 'incorrect password', 'username': 'unknown user ID', 'captcha': 'incorrect CAPTCHA'}
    reason_summary = ', '.join(f'{failure_reasons.count(reason)} {reason_labels.get(reason, reason)}' for reason in dict.fromkeys(failure_reasons))
    account_known = bool(metadata.get('account_known'))
    target_username = metadata.get('target_username') if account_known else None

    if rules['unusual_login']:
        score = min(96, 78 + max(0, failed_count - 3) * 3 + (5 if 'captcha' in failure_reasons else 0))
    else:
        score = max(round(probability * 100), 76 if matched else 0)
    level = 'Critical' if score >= 90 else 'High' if score >= 70 else 'Medium'
    signals = []
    if rules['unusual_login']:
        signals = [f'{failed_count} unsuccessful sign-in attempts within five minutes']
        if reason_summary:
            signals.append(f'Attempt types: {reason_summary}')
        if not account_known:
            signals.append('The entered user ID did not match a sample account; no individual account could be identified.')
    else:
        signals = [
            'login from an unfamiliar region was simulated' if rules['suspicious_login'] else None,
            'restricted resource access was simulated' if rules['unauthorized_access'] else None,
            'high request volume was simulated' if rules['high_request_volume'] else None,
            'document integrity change was simulated' if rules['document_modification'] else None,
            f'trained model score {probability:.2f}' if probability >= 0.5 else None,
        ]
        signals = [signal for signal in signals if signal]

    domain_name = DOMAINS[event['organization_domain']]['org']
    timeline = []
    for row in reversed(failed_rows[-9:]):
        timeline.append({'timestamp': row['timestamp'], 'username': row['username'], 'event_type': row['event_type'],
                         'source_ip': row['source_ip'], 'details': row['details']})
    timeline.append({'timestamp': event['timestamp'], 'username': event['username'], 'event_type': event_type,
                     'source_ip': event['source_ip'], 'details': event['details']})
    related_users = sorted({row['username'] for row in failed_rows} | {event['username']})
    if account_known and target_username:
        investigation = {
            'status': 'complete', 'finding': f'{failed_count} failed sign-in checks for the identified account from {event["source_ip"]}.',
            'account_known': True, 'target_username': target_username, 'involved_users': related_users, 'timeline': timeline,
        }
        try:
            integrity = document_integrity(target_username)
            document_agent = {'status': 'complete', 'finding': f"Private sample file {integrity['filename']} SHA-256 {integrity['status'].lower()}.", **integrity}
        except HTTPException:
            document_agent = {'status': 'unavailable', 'finding': 'No private sample file was available for integrity verification.'}
        recommendations = ['Require an immediate password change', 'Review the recent sign-in timeline', 'Revoke existing sessions after approval']
    else:
        investigation = {
            'status': 'complete', 'finding': f'{failed_count} unsuccessful sign-in attempts used an unrecognized ID from {event["source_ip"]}; the account owner is unknown.',
            'account_known': False, 'target_username': None, 'involved_users': [], 'attempted_user_id': event['username'],
            'attempted_user_ids': related_users, 'timeline': timeline,
        }
        document_agent = {'status': 'not_applicable', 'finding': 'An account could not be identified, so no user document was accessed.'}
        recommendations = ['Review the domain-level sign-in attempts', 'Check whether a user ID was mistyped']

    if not rules['unusual_login']:
        investigation = {'status': 'complete', 'finding': f"Reviewed {len(prior) + 1} related event(s) for {event['username']} from {event['source_ip']}.", 'timeline': timeline, 'involved_users': related_users}
        document_agent = {'status': 'complete', 'finding': 'No document-change signal in this event.'}
        recommendations = ['Review the account and related events']

    agents = {
        'detection': {'status': 'complete', 'finding': 'Unusual login: three or more unsuccessful sign-in checks.' if rules['unusual_login'] else f"Matched: {', '.join(matched) if matched else 'trained model threshold'}"},
        'investigation': investigation,
        'risk_assessment': {'status': 'complete', 'score': score, 'level': level, 'signals': signals, 'explanation': '; '.join(signals)},
        'document_verification': document_agent,
        'response': {'status': 'pending_human_approval', 'finding': 'Recommendations are waiting for a human reviewer.', 'recommended_actions': recommendations,
                     'password_change_available': bool(rules['unusual_login'] and account_known), 'approved_action': None},
    }
    return {
        'alert_id': secrets.token_hex(12), 'event_id': event['event_id'],
        'organization_domain': event['organization_domain'], 'organization_name': domain_name,
        'username': target_username or event['username'], 'event_type': 'unusual_login' if rules['unusual_login'] else event_type,
        'source_ip': event['source_ip'], 'timestamp': event['timestamp'], 'risk_score': score, 'risk_level': level,
        'incident_status': 'Needs human review',
        'summary': '; '.join(signals) or 'Suspicious activity matched the model threshold.',
        'agents': agents, 'created_at': now_iso(),
    }

def store_alert(alert: dict[str, Any]) -> None:
    with db() as connection:
        connection.execute('''INSERT OR IGNORE INTO alerts(
            alert_id,event_id,organization_domain,organization_name,username,event_type,source_ip,
            timestamp,risk_score,risk_level,incident_status,summary,agents_json,created_at
        ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)''', (
            alert['alert_id'], alert['event_id'], alert['organization_domain'], alert['organization_name'],
            alert['username'], alert['event_type'], alert['source_ip'], alert['timestamp'], alert['risk_score'],
            alert['risk_level'], alert['incident_status'], alert['summary'], json.dumps(alert['agents']), alert['created_at'],
        ))


def update_delivery(event_ids: list[str], status: str, error: str | None, result: str | None = None) -> None:
    if not event_ids:
        return
    placeholders = ','.join('?' for _ in event_ids)
    with db() as connection:
        connection.execute(f'''UPDATE events SET delivery_status=?, attempts=attempts+1,
            last_attempt_at=?, last_error=?, sentinel_result=COALESCE(?, sentinel_result)
            WHERE event_id IN ({placeholders})''', [status, now_iso(), error, result, *event_ids])


async def forward_batch(events: list[dict[str, Any]]) -> dict[str, Any]:
    if not events:
        return {'delivery_status': 'not_configured', 'accepted': 0, 'message': 'No events to send.'}
    if not SENTINEL_API_URL:
        update_delivery([event['event_id'] for event in events], 'not_configured', 'SENTINEL_API_URL is not configured')
        return {'delivery_status': 'not_configured', 'accepted': 0, 'message': 'Set SENTINEL_API_URL to enable forwarding.'}
    headers = {'Content-Type': 'application/json'}
    if SENTINEL_API_KEY:
        headers['Authorization'] = f'Bearer {SENTINEL_API_KEY}'
    try:
        async with httpx.AsyncClient(timeout=5.0, follow_redirects=False) as client:
            response = await client.post(SENTINEL_API_URL, json={'events': events}, headers=headers)
        if not response.is_success:
            error = f'Sentinel endpoint returned HTTP {response.status_code}'
            update_delivery([event['event_id'] for event in events], 'failed', error)
            return {'delivery_status': 'failed', 'accepted': 0, 'message': error}
        result = response.text[:4000]
        update_delivery([event['event_id'] for event in events], 'sent', None, result)
        return {'delivery_status': 'sent', 'accepted': len(events), 'message': 'Sentinel endpoint accepted the event batch.'}
    except (httpx.HTTPError, ValueError) as error:
        message = f'{type(error).__name__}: {error}'[:300]
        update_delivery([event['event_id'] for event in events], 'failed', message)
        return {'delivery_status': 'failed', 'accepted': 0, 'message': message}


async def retry_worker() -> None:
    while True:
        await asyncio.sleep(8)
        try:
            with db() as connection:
                rows = connection.execute('''SELECT * FROM events WHERE delivery_status IN ('pending','failed')
                    AND attempts < 8 ORDER BY created_at LIMIT 50''').fetchall()
            due = []
            current = time.time()
            for row in rows:
                attempts = row['attempts']
                if not row['last_attempt_at']:
                    due.append(row)
                    continue
                try:
                    last_attempt = datetime.fromisoformat(row['last_attempt_at']).timestamp()
                except ValueError:
                    last_attempt = 0
                if current - last_attempt >= min(300, 2 ** attempts * 5):
                    due.append(row)
            for start in range(0, len(due), 25):
                await forward_batch([event_dict(row) for row in due[start:start + 25]])
        except asyncio.CancelledError:
            raise
        except Exception:
            await asyncio.sleep(2)


@asynccontextmanager
async def lifespan(_: FastAPI):
    init_db()
    initialize_lotl_database()
    worker = asyncio.create_task(retry_worker())
    try:
        yield
    finally:
        worker.cancel()
        try:
            await worker
        except asyncio.CancelledError:
            pass


app = FastAPI(title='CivicShield Demo API', version='1.0.0', lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=['http://localhost:4174', 'http://127.0.0.1:4174', 'http://localhost:4173', 'http://127.0.0.1:4173'],
    allow_credentials=True,
    allow_methods=['GET', 'POST', 'OPTIONS'],
    allow_headers=['Content-Type', 'Authorization'],
)
app.include_router(lotl_router)


class LoginInput(BaseModel):
    organization_domain: str
    username: str = Field(min_length=3, max_length=48)
    password: str = Field(min_length=1, max_length=256)
    captcha_challenge_id: str = Field(min_length=12, max_length=80)
    captcha_answer: str = Field(min_length=1, max_length=12)


class ChangePasswordInput(BaseModel):
    new_password: str = Field(min_length=12, max_length=256)


class BatchInput(BaseModel):
    events: list[dict[str, Any]] = Field(min_length=1, max_length=250)


class BankLookupInput(BaseModel):
    account_number: str = Field(min_length=8, max_length=32)
    access_code: str = Field(min_length=4, max_length=4)


class DocumentUnlockInput(BaseModel):
    code: str = Field(min_length=8, max_length=32)


def enforce_login_rate_limit(ip: str) -> None:
    now = time.time()
    attempts = [stamp for stamp in login_attempts.get(ip, []) if now - stamp < 300]
    if len(attempts) >= 12:
        raise HTTPException(status_code=429, detail='Too many sign-in attempts. Try again in five minutes.')
    login_attempts[ip] = attempts


async def record_failed_signin(domain: str, attempted_username: str, ip: str, failure_type: str) -> dict[str, Any]:
    normalized = attempted_username.strip().lower()[:48] or 'unknown'
    with db() as connection:
        account = connection.execute('SELECT username FROM users WHERE username=? COLLATE NOCASE AND domain=?',
                                     (normalized, domain)).fetchone()
    known_account = account is not None
    username = account['username'] if account else normalized
    event_type = 'captcha_failed' if failure_type == 'captcha' else 'login_failed'
    descriptions = {
        'captcha': 'CAPTCHA check failed.',
        'username': 'Unknown user ID entered.',
        'password': 'Incorrect password entered for a known user ID.' if known_account else 'Invalid user ID or password entered.',
    }
    metadata = {
        'failure_reason': failure_type,
        'account_known': known_account,
        'target_username': username if known_account else None,
        'attempted_username': normalized,
    }
    event = record_event(domain, username, ip, event_type, '/auth/login', 'Medium', descriptions[failure_type], metadata)
    delivery = await forward_batch([event])
    return {'event_id': event['event_id'], 'delivery': delivery, 'account_known': known_account}


def set_session(response: Response, username: str) -> None:
    raw_token = secrets.token_urlsafe(32)
    expires = datetime.now(timezone.utc) + timedelta(hours=SESSION_HOURS)
    with db() as connection:
        connection.execute('INSERT INTO sessions(token_hash,username,expires_at,created_at) VALUES(?,?,?,?)',
                           (hashlib.sha256(raw_token.encode()).hexdigest(), username, expires.isoformat(timespec='seconds'), now_iso()))
    response.set_cookie(COOKIE_NAME, raw_token, httponly=True, secure=COOKIE_SECURE,
                        samesite='strict', max_age=SESSION_HOURS * 3600, path='/')


@app.get('/api/health')
def health() -> dict[str, Any]:
    return {'status': 'ok', 'database': 'sqlite', 'sentinel_endpoint_configured': bool(SENTINEL_API_URL),
            'model_loaded': bool(model_data.get('trees')), 'live_government_connection': False}


@app.get('/api/domains')
def domains() -> list[dict[str, str]]:
    return [{'id': key, **value} for key, value in DOMAINS.items()]


@app.get('/api/auth/captcha')
def issue_captcha() -> dict[str, str]:
    now = time.time()
    for token, (_, expires_at) in list(captcha_challenges.items()):
        if expires_at <= now:
            captcha_challenges.pop(token, None)
    alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'
    code = ''.join(secrets.choice(alphabet) for _ in range(6))
    token = secrets.token_urlsafe(24)
    captcha_challenges[token] = (code, now + 300)
    return {'challenge_id': token, 'code': code}


def sample_profile_for(user: sqlite3.Row) -> dict[str, str]:
    try:
        index = int(user['username'].rsplit('_', 1)[1]) - 1001
        row = SAMPLE_PROFILES[user['domain']][index]
    except (KeyError, IndexError, ValueError):
        raise HTTPException(status_code=404, detail='No sample profile is assigned to this account.')
    reference, city, status, kind_label, kind, detail_label, detail, extra_label, extra = row[:9]
    return {
        'username': user['username'], 'domain': user['domain'], 'reference': reference,
        'name': user['display_name'], 'city': city, 'status': status,
        'kindLabel': kind_label, 'kind': kind, 'detailLabel': detail_label,
        'detail': detail, 'extraLabel': extra_label, 'extra': extra,
    }


@app.get('/api/profile')
def customer_profile(request: Request) -> dict[str, str]:
    user = require_user(request)
    profile = sample_profile_for(user)
    if user['domain'] == 'banking':
        profile.pop('detail', None)
        profile.pop('detailLabel', None)
    return profile


@app.post('/api/profile/bank-lookup')
def bank_balance(body: BankLookupInput, request: Request) -> dict[str, str]:
    user = require_user(request)
    if user['domain'] != 'banking':
        raise HTTPException(status_code=403, detail='This lookup is only available in the banking demo.')
    profile = sample_profile_for(user)
    row = SAMPLE_PROFILES['banking'][int(user['username'].rsplit('_', 1)[1]) - 1001]
    if (not hmac.compare_digest(body.account_number.strip().casefold(), profile['reference'].casefold())
            or not hmac.compare_digest(body.access_code.strip(), profile['reference'][-4:])):
        raise HTTPException(status_code=403, detail='The sample details do not match your signed-in demo account.')
    return {'balance': row[9], 'name': profile['name'], 'city': profile['city'],
            'reference': profile['reference'], 'kind': profile['kind'], 'detail': profile['detail']}


@app.post('/api/profile/document')
def private_document(body: DocumentUnlockInput, request: Request) -> FileResponse:
    user = require_user(request)
    try:
        person_id = int(user['username'].rsplit('_', 1)[1])
    except (IndexError, ValueError):
        raise HTTPException(status_code=403, detail='The file access code is incorrect.')
    expected_code = FILE_ACCESS_CODES.get(person_id)
    supplied_code = body.code.strip().upper()
    if not expected_code or not hmac.compare_digest(supplied_code, expected_code):
        raise HTTPException(status_code=403, detail='The file access code is incorrect.')
    integrity = document_integrity(user['username'])
    return FileResponse(HERE / 'private_files' / integrity['filename'], media_type='text/plain; charset=utf-8',
                        filename=integrity['filename'], headers={'Cache-Control': 'private, no-store'})


@app.get('/api/profile/document/integrity')
def private_document_integrity(request: Request) -> dict[str, str]:
    user = require_user(request)
    return document_integrity(user['username'])


@app.post('/api/auth/login')
async def login(body: LoginInput, request: Request, response: Response) -> dict[str, Any]:
    if body.organization_domain not in DOMAINS:
        raise HTTPException(status_code=400, detail='Choose a valid service portal.')
    ip = client_ip(request)
    enforce_login_rate_limit(ip)
    challenge = captcha_challenges.pop(body.captcha_challenge_id, None)
    if not challenge or challenge[1] <= time.time() or not hmac.compare_digest(body.captcha_answer.strip().upper(), challenge[0]):
        login_attempts[ip] = login_attempts.get(ip, []) + [time.time()]
        failed = await record_failed_signin(body.organization_domain, body.username, ip, 'captcha')
        raise HTTPException(status_code=401, detail={'message': 'Access denied. The CAPTCHA is incorrect or expired.',
                                                     'event_id': failed['event_id'], 'delivery_status': failed['delivery']['delivery_status']})
    with db() as connection:
        user = connection.execute('SELECT * FROM users WHERE username=? COLLATE NOCASE AND domain=?',
                                  (body.username.strip().lower(), body.organization_domain)).fetchone()
    if not user or not verify_password(body.password, user['password_hash']):
        login_attempts[ip] = login_attempts.get(ip, []) + [time.time()]
        failure_type = 'password' if user else 'username'
        failed = await record_failed_signin(body.organization_domain, body.username, ip, failure_type)
        raise HTTPException(status_code=401, detail={'message': 'Sign-in failed. Check the demo username and password.',
                                                     'event_id': failed['event_id'], 'delivery_status': failed['delivery']['delivery_status']})
    login_attempts[ip] = []
    set_session(response, user['username'])
    event = record_event(user['domain'], user['username'], ip, 'login_success', '/auth/login', 'Info', 'Demo account signed in successfully.')
    delivery = await forward_batch([event])
    return {'user': {'username': user['username'], 'display_name': user['display_name'], 'domain': user['domain'],
                     'must_change_password': bool(user['must_change_password'])},
            'delivery': delivery}


@app.get('/api/auth/me')
def me(request: Request) -> dict[str, Any]:
    user = require_user(request, allow_password_reset=True)
    return {'username': user['username'], 'display_name': user['display_name'], 'domain': user['domain'],
            'must_change_password': bool(user['must_change_password'])}


@app.post('/api/auth/logout')
async def logout(request: Request, response: Response) -> dict[str, Any]:
    user = get_session_user(request)
    if user:
        event = record_event(user['domain'], user['username'], client_ip(request), 'logout', '/auth/logout', 'Info', 'Demo account signed out.')
        await forward_batch([event])
        raw_token = request.cookies.get(COOKIE_NAME, '')
        with db() as connection:
            connection.execute('DELETE FROM sessions WHERE token_hash=?', (hashlib.sha256(raw_token.encode()).hexdigest(),))
    response.delete_cookie(COOKIE_NAME, path='/')
    return {'status': 'signed_out'}


@app.post('/api/auth/change-password')
async def change_password(body: ChangePasswordInput, request: Request) -> dict[str, str]:
    user = require_user(request, allow_password_reset=True)
    if body.new_password == DEMO_PASSWORD:
        raise HTTPException(status_code=400, detail='Choose a new password different from the shared demo password.')
    with db() as connection:
        connection.execute('UPDATE users SET password_hash=?,must_change_password=0 WHERE username=?',
                           (hash_password(body.new_password), user['username']))
    event = record_event(user['domain'], user['username'], client_ip(request), 'password_changed', '/auth/change-password',
                         'Info', 'The sample user completed a required password change.')
    await forward_batch([event])
    return {'status': 'changed', 'message': 'Your sample account password has been updated.'}


def sentinel_authorized(request: Request) -> bool:
    if SENTINEL_API_KEY:
        return hmac.compare_digest(request.headers.get('authorization', ''), f'Bearer {SENTINEL_API_KEY}')
    host = request.client.host if request.client else ''
    return host in ('127.0.0.1', '::1', 'localhost', 'testclient')


@app.post('/api/sentinel/events/batch')
def sentinel_receive(body: BatchInput, request: Request) -> dict[str, Any]:
    if not sentinel_authorized(request):
        raise HTTPException(status_code=401, detail='Sentinel API authentication is required.')
    new_alerts = []
    for incoming in body.events:
        required = ('event_id', 'timestamp', 'organization_domain', 'username', 'source_ip', 'event_type', 'resource', 'severity', 'details')
        if any(not incoming.get(field) for field in required):
            raise HTTPException(status_code=422, detail='Each event must include timestamp, organization_domain, username, source_ip, event_type, resource, severity, and details.')
        domain = incoming['organization_domain']
        if domain not in DOMAINS:
            raise HTTPException(status_code=422, detail='Unknown organization_domain.')
        with db() as connection:
            existing = connection.execute('SELECT * FROM events WHERE event_id=?', (incoming['event_id'],)).fetchone()
            if not existing:
                connection.execute('''INSERT INTO events(event_id,timestamp,organization_domain,username,source_ip,event_type,
                    resource,severity,details,metadata_json,delivery_status,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)''',
                    (incoming['event_id'], incoming['timestamp'], domain, incoming['username'], incoming['source_ip'],
                     incoming['event_type'], incoming['resource'], incoming['severity'], incoming['details'],
                     json.dumps(incoming.get('metadata', {})), 'received', now_iso()))
                existing = connection.execute('SELECT * FROM events WHERE event_id=?', (incoming['event_id'],)).fetchone()
            since = (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat(timespec='seconds')
            metadata = incoming.get('metadata', {})
            if incoming['event_type'] in ('login_failed', 'captcha_failed') and metadata.get('account_known') is False:
                rows = connection.execute('''SELECT * FROM events WHERE organization_domain=? AND source_ip=? AND timestamp>=?
                    AND event_id<>? ORDER BY timestamp DESC LIMIT 100''', (domain, incoming['source_ip'], since, incoming['event_id'])).fetchall()
                prior = []
                for row in rows:
                    if row['event_type'] not in ('login_failed', 'captcha_failed'):
                        continue
                    try:
                        if json.loads(row['metadata_json'] or '{}').get('account_known') is False:
                            prior.append(row)
                    except (TypeError, json.JSONDecodeError):
                        continue
            else:
                prior = connection.execute('''SELECT * FROM events WHERE username=? AND organization_domain=? AND timestamp>=?
                    AND event_id<>? ORDER BY timestamp DESC LIMIT 50''', (incoming['username'], domain, since, incoming['event_id'])).fetchall()
        event = event_dict(existing) | {'metadata': incoming.get('metadata', {})}
        alert = analyze_event(event, prior)
        if alert:
            if alert['event_type'] == 'unusual_login':
                window_start = (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat(timespec='seconds')
                with db() as connection:
                    recent_alerts = connection.execute('''SELECT username,agents_json FROM alerts WHERE organization_domain=?
                        AND source_ip=? AND event_type='unusual_login' AND created_at>=?''',
                        (alert['organization_domain'], alert['source_ip'], window_start)).fetchall()
                target_known = bool(alert['agents']['investigation'].get('account_known'))
                duplicate = False
                for recent in recent_alerts:
                    previous_investigation = json.loads(recent['agents_json']).get('investigation', {})
                    if bool(previous_investigation.get('account_known')) == target_known and (not target_known or recent['username'] == alert['username']):
                        duplicate = True
                        break
                if duplicate:
                    continue
            store_alert(alert)
            new_alerts.append(alert)
    return {'accepted': len(body.events), 'alerts': new_alerts, 'processed_at': now_iso()}


@app.get('/api/sentinel/alerts')
def sentinel_alerts(request: Request, since: str | None = None) -> list[dict[str, Any]]:
    if not sentinel_authorized(request):
        raise HTTPException(status_code=401, detail='Sentinel API authentication is required.')
    with db() as connection:
        if since:
            rows = connection.execute('SELECT * FROM alerts WHERE created_at>? ORDER BY created_at DESC LIMIT 100', (since,)).fetchall()
        else:
            rows = connection.execute('SELECT * FROM alerts ORDER BY created_at DESC LIMIT 100').fetchall()
    return [dict(row) | {'agents': json.loads(row['agents_json'])} for row in rows]


@app.post('/api/sentinel/alerts/{alert_id}/require-password-change')
async def require_password_change(alert_id: str, request: Request) -> dict[str, Any]:
    if not sentinel_authorized(request):
        raise HTTPException(status_code=401, detail='Sentinel API authentication is required.')
    with db() as connection:
        alert = connection.execute('SELECT * FROM alerts WHERE alert_id=?', (alert_id,)).fetchone()
        if not alert:
            raise HTTPException(status_code=404, detail='Alert not found.')
        agents = json.loads(alert['agents_json'])
        investigation = agents.get('investigation', {})
        target_username = investigation.get('target_username')
        if alert['event_type'] != 'unusual_login' or not target_username:
            raise HTTPException(status_code=409, detail='This alert is not linked to a known user account.')
        target = connection.execute('SELECT username,domain FROM users WHERE username=?', (target_username,)).fetchone()
        if not target:
            raise HTTPException(status_code=404, detail='The affected demo account no longer exists.')
        connection.execute('UPDATE users SET must_change_password=1 WHERE username=?', (target_username,))
        connection.execute('DELETE FROM sessions WHERE username=?', (target_username,))
        agents.setdefault('response', {})['status'] = 'approved'
        agents['response']['approved_action'] = 'Require an immediate password change; existing sessions were revoked.'
        agents['response']['finding'] = 'A human reviewer approved a required password change.'
        connection.execute('UPDATE alerts SET incident_status=?,agents_json=? WHERE alert_id=?',
                           ('Password change required', json.dumps(agents), alert_id))
    event = record_event(target['domain'], target_username, client_ip(request), 'password_change_required',
                         '/sentinel/approved-response', 'High', 'A SENTINEL reviewer required a password change and revoked current sessions.',
                         {'alert_id': alert_id, 'human_approved': True})
    delivery = await forward_batch([event])
    return {'status': 'approved', 'username': target_username, 'delivery': delivery}


@app.get('/api/sentinel/events')
def sentinel_events(request: Request, limit: int = 100) -> list[dict[str, Any]]:
    if not sentinel_authorized(request):
        raise HTTPException(status_code=401, detail='Sentinel API authentication is required.')
    limit = max(1, min(limit, 500))
    with db() as connection:
        rows = connection.execute('SELECT * FROM events ORDER BY created_at DESC LIMIT ?', (limit,)).fetchall()
    return [event_dict(row) for row in rows]


@app.get('/api/datasets')
def dataset_catalog() -> dict[str, Any]:
    evaluation_path = PORTAL_ROOT.parent / 'artifacts' / 'evaluation.json'
    evaluation = json.loads(evaluation_path.read_text(encoding='utf-8')) if evaluation_path.exists() else {}
    catalog = []
    for model_domain, domain_name in TRAINED_DOMAIN_NAMES.items():
        csv_path = PORTAL_ROOT.parent / 'data' / 'by_domain' / f'{model_domain}.csv'
        record_count = max(0, sum(1 for _ in csv_path.open(encoding='utf-8')) - 1) if csv_path.exists() else 0
        catalog.append({'id': model_domain, 'name': domain_name, 'records': record_count,
                        'download_url': f'/data/by_domain/{model_domain}.csv'})
    return {'domains': catalog, 'total_records': sum(item['records'] for item in catalog),
            'overall_metrics': evaluation.get('overall', {}), 'evaluation_note': evaluation.get('evaluation_note', '')}


@app.get('/data/all_domains.csv')
def all_domain_dataset() -> FileResponse:
    target = PORTAL_ROOT.parent / 'data' / 'all_domains.csv'
    if not target.exists():
        raise HTTPException(status_code=404, detail='Synthetic dataset is not available.')
    return FileResponse(target, media_type='text/csv', filename='civicshield-all-domain-synthetic-events.csv')


@app.get('/data/by_domain/{domain_id}.csv')
def domain_dataset(domain_id: str) -> FileResponse:
    if domain_id not in TRAINED_DOMAIN_NAMES:
        raise HTTPException(status_code=404, detail='Unknown dataset domain.')
    target = PORTAL_ROOT.parent / 'data' / 'by_domain' / f'{domain_id}.csv'
    if not target.exists():
        raise HTTPException(status_code=404, detail='Synthetic dataset is not available.')
    return FileResponse(target, media_type='text/csv', filename=f'civicshield-{domain_id}-synthetic-events.csv')


@app.get('/artifacts/evaluation.json')
def evaluation_artifact() -> FileResponse:
    target = PORTAL_ROOT.parent / 'artifacts' / 'evaluation.json'
    if not target.exists():
        raise HTTPException(status_code=404, detail='Model evaluation is not available.')
    return FileResponse(target, media_type='application/json', filename='sentinel-model-evaluation.json')
