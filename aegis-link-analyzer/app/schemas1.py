from pydantic import BaseModel, HttpUrl
from typing import Dict, Optional, Any

# What the user sends to us
class LinkRequest(BaseModel):
    url: HttpUrl

# The detailed report we send back
class ScanResult(BaseModel):
    url: str
    risk_level: str
    confidence_score: float
    message: str
    detection_counts: Dict[str, int]
    scan_date: str
    scanners_count: int
    
    # Visuals from URLScan
    report_url: Optional[str] = None
    screenshot_url: Optional[str] = None
    
    # NEW FIELD: VirusTotal Report Link
    virustotal_report: Optional[str] = None
    
    scan_id: Optional[str] = None