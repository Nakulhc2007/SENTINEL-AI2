from __future__ import annotations

import secrets
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

class ActivityEvent(BaseModel):
    model_config = ConfigDict(extra='ignore')

    event_id: str = Field(default_factory=lambda: f'EVT-{secrets.token_hex(6)}', min_length=4, max_length=100)
    organization_domain: str = Field(default='corporate', max_length=40)
    timestamp: datetime
    username: str = Field(min_length=1, max_length=100)
    user_role: str = Field(default='Unknown', max_length=100)
    source_ip: str = Field(default='unknown', max_length=64)
    device: str = Field(default='unknown', max_length=120)
    login_success: bool | None = None
    process_category: str = Field(default='administrative_tool', max_length=100)
    action: str = Field(min_length=1, max_length=160)
    resource: str = Field(default='unknown', max_length=240)
    document_hash_before: str | None = Field(default=None, pattern='^[a-fA-F0-9]{64}$')
    document_hash_after: str | None = Field(default=None, pattern='^[a-fA-F0-9]{64}$')
    permission_level: str = Field(default='standard', max_length=80)
    data_volume_mb: float = Field(default=0, ge=0, le=10_000_000)
    maintenance_ref: str | None = Field(default=None, max_length=120)
    outcome: str = Field(default='success', max_length=80)
    business_criticality: str = Field(default='medium', max_length=40)
    session_id: str = Field(default='default-session', max_length=120)
    synthetic_baseline: bool = False

    @field_validator('timestamp', mode='before')
    @classmethod
    def parse_timestamp(cls, value: Any) -> Any:
        if isinstance(value, datetime):
            return value
        if not value:
            raise ValueError('A timestamp is required for each activity event.')
        if isinstance(value, str):
            return datetime.fromisoformat(value.strip().replace('Z', '+00:00'))
        return value

    @field_validator('timestamp')
    @classmethod
    def ensure_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)


class MaintenanceInput(BaseModel):
    maintenance_id: str | None = Field(default=None, max_length=100)
    date: str = Field(min_length=10, max_length=10)
    start_time: str = Field(min_length=5, max_length=5)
    end_time: str = Field(min_length=5, max_length=5)
    authorized_users: list[str] = Field(min_length=1, max_length=100)
    approved_actions: list[str] = Field(min_length=1, max_length=100)
    approved_resources: list[str] = Field(min_length=1, max_length=100)
    description: str = Field(min_length=3, max_length=500)
    change_reference: str = Field(min_length=2, max_length=120)


class DecisionInput(BaseModel):
    decision: str = Field(pattern='^(approve|reject|review)$')
    approver: str = Field(min_length=2, max_length=100)
    note: str = Field(default='', max_length=500)
