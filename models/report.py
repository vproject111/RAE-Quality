# models/report.py
from pydantic import BaseModel, Field
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from enum import Enum
from uuid import UUID, uuid4

def _utc_now() -> datetime:
    return datetime.now(timezone.utc)

class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class Verdict(str, Enum):
    PASSED = "PASSED"
    REJECTED = "REJECTED"
    ESCALATED = "ESCALATED"
    ERROR = "ERROR"

class QualityIssue(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid4())[:8])
    engine: str
    severity: Severity
    message: str
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    fix_suggestion: Optional[str] = None

class AuditResult(BaseModel):
    audit_id: UUID = Field(default_factory=uuid4)
    timestamp: datetime = Field(default_factory=_utc_now)
    verdict: Verdict
    confidence: float = Field(ge=0.0, le=1.0)
    score: float = Field(ge=0.0, le=1.0)
    issues: List[QualityIssue] = []
    reasoning: str
    tier_reached: int = 1
    seniority_level: str = "junior"
    metadata: Dict[str, Any] = {}

class ScanReport(BaseModel):
    project: str
    timestamp: datetime = Field(default_factory=_utc_now)
    score: float 
    issues: List[QualityIssue]
    metrics: Dict[str, Any]
    verdict: Optional[Verdict] = None
    meta: Dict[str, Any] = {}
