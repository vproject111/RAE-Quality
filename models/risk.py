# packages/rae-quality/models/risk.py
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import UUID, uuid4
from pydantic import BaseModel, Field

class RiskSeverity(str, Enum):
    P0 = "P0"  # Critical (Loss of data, broken production prints, massive financial drift)
    P1 = "P1"  # High (Price calc error, scene save error, broken export, security bug)
    P2 = "P2"  # Medium (Feature malfunction with workaround, non-critical geometry)
    P3 = "P3"  # Low (Cosmetic UX, minor layout difference)

class PathStatus(str, Enum):
    PASSED = "PASSED"
    FAILED = "FAILED"
    PARTIAL = "PARTIAL"
    UNTESTED = "UNTESTED"

class DeploymentGateVerdict(str, Enum):
    LEVEL_1_APPROVED = "LEVEL_1_APPROVED"  # Safe to deploy automatically
    LEVEL_2_WARNING = "LEVEL_2_WARNING"    # Requires Tech Lead sign-off
    LEVEL_3_BLOCKED = "LEVEL_3_BLOCKED"    # Hard deployment block

class RiskPathItem(BaseModel):
    id: str
    name: str
    system: str  # dreamsoft_factory, editornext, rae-suite
    weight: int = Field(ge=1, le=10)
    severity: RiskSeverity
    verification_score: float = Field(default=0.0, ge=0.0, le=1.0)
    status: PathStatus = PathStatus.UNTESTED
    test_suite: str
    details: Dict[str, Any] = Field(default_factory=dict)

class RiskCoverageResult(BaseModel):
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    total_risk_coverage: float = Field(ge=0.0, le=100.0)
    weighted_score: float
    total_weight: int
    paths: List[RiskPathItem]
    p0_violations: int = 0
    p1_violations: int = 0
    p2_violations: int = 0
    p3_violations: int = 0

class DeploymentGateResult(BaseModel):
    verdict: DeploymentGateVerdict
    can_deploy: bool
    risk_coverage_pct: float
    p0_defects_count: int
    p1_defects_count: int
    blockers: List[str] = Field(default_factory=list)
    warnings: List[str] = Field(default_factory=list)
    recommendations: List[str] = Field(default_factory=list)
    timestamp: datetime = Field(default_factory=datetime.utcnow)

class PDFDtpAuditResult(BaseModel):
    document_id: str = Field(default_factory=lambda: str(uuid4())[:8])
    is_production_ready: bool
    score: float = Field(ge=0.0, le=1.0)
    trimbox_mm: Dict[str, float]
    bleedbox_mm: Dict[str, float]
    has_valid_bleed: bool
    dpi_min: float
    has_pure_black_text: bool
    spot_colors: List[str] = Field(default_factory=list)
    overprint_valid: bool
    fonts_embedded: bool
    issues: List[str] = Field(default_factory=list)
    warnings: List[str] = Field(default_factory=list)

class DefectItem(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid4())[:8])
    title: str
    severity: RiskSeverity
    detected_at: str  # "CI" or "PRODUCTION"
    created_at: datetime = Field(default_factory=datetime.utcnow)
    resolved_at: Optional[datetime] = None
    system: str

class DefectMetrics(BaseModel):
    total_defects: int
    production_defects: int
    ci_defects: int
    defect_escape_rate: float  # (production / total) * 100
    severity_weighted_score: int  # 100*P0 + 25*P1 + 5*P2 + 1*P3
    regression_rate: float
    mttr_hours: float
