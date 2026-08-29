"""app/schemas/scan.py — Scan history Pydantic schemas."""
from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel


class ScanHistoryEntry(BaseModel):
    id: uuid.UUID
    entry_type: str
    verdict: str
    risk_level: str
    scanned_at: datetime

    class Config:
        from_attributes = True


class ScanHistoryResponse(BaseModel):
    entries: list[ScanHistoryEntry]
    total: int
    period_days: int = 30


class ScanStats(BaseModel):
    total_scans: int
    threats_found: int
    links_scanned: int
    credentials_checked: int
    profiles_analysed: int
    smishing_detected: int
