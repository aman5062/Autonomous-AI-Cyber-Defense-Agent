from pydantic import BaseModel
from typing import Optional


class BlockIPRequest(BaseModel):
    ip: str
    reason: str = "Manual block"
    duration: int = 3600


class UnblockIPRequest(BaseModel):
    ip: str


class DefenseModeRequest(BaseModel):
    auto_defense: Optional[bool] = None
    dry_run: Optional[bool] = None


class SimulateRequest(BaseModel):
    attack_type: str = "all"  # all | sql_injection | xss | path_traversal | brute_force
