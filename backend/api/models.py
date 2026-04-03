"""
Pydantic models for API request / response validation.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, field_validator
import ipaddress


class BlockIPRequest(BaseModel):
    ip: str
    reason: str = "Manual block"
    duration: int = Field(default=3600, ge=60, le=604800)

    @field_validator("ip")
    @classmethod
    def validate_ip(cls, v: str) -> str:
        try:
            ipaddress.ip_address(v)
            return v
        except ValueError:
            raise ValueError(f"Invalid IP address: {v}")


class UnblockIPRequest(BaseModel):
    ip: str

    @field_validator("ip")
    @classmethod
    def validate_ip(cls, v: str) -> str:
        try:
            ipaddress.ip_address(v)
            return v
        except ValueError:
            raise ValueError(f"Invalid IP address: {v}")


class WhitelistRequest(BaseModel):
    ip: str
    reason: str = ""


class DefenseModeRequest(BaseModel):
    auto_block: Optional[bool] = None
    dry_run: Optional[bool] = None


class AttackResponse(BaseModel):
    id: int
    timestamp: Optional[str]
    ip: str
    method: str
    path: str
    status: int
    attack_type: Optional[str]
    severity: Optional[str]
    blocked: bool
    user_agent: Optional[str]
    explanation: Optional[str] = None
    impact: Optional[str] = None
    mitigation: Optional[Any] = None
    code_fix: Optional[Any] = None


class BlockedIPResponse(BaseModel):
    id: int
    ip: str
    attack_type: Optional[str]
    severity: Optional[str]
    block_time: str
    unblock_time: Optional[str]
    status: str
    reason: Optional[str]
    blocked_by: str


class StatsResponse(BaseModel):
    total_attacks: int
    by_type: Dict[str, int]
    by_severity: Dict[str, int]
    blocked_count: int
    timeline: List[Dict[str, Any]]


class HealthResponse(BaseModel):
    status: str
    timestamp: str
    services: Dict[str, str]
    defense_mode: Dict[str, bool]
