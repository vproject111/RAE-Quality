# packages/rae-quality/models/security_v2.py
"""
RAE-Quality 2.0 Data Models & Contracts.
Implements the complete specification from docs/poziom-bezpieczeństwa-kodu.md:
- 4-stage Quality Gateway (PASS, REPAIR, BLOCK, REVIEW)
- 3 Control Types (deterministic, ai_semantic, systemic)
- 12 Control Modules (198 catalog items) + 12 Agentic AI/SaaS items + 9 RAE-EDITOR-SECURITY rules
- Rule Engine schema (RAE-SEC-001..210, RAE-EDT-001..009)
- SARIF 2.1.0 normalized scanner output
- Dual Risk Assessment (Quality Score 0-100 + Mandatory Gates)
- Auto-Repair state machine (max 3 attempts -> HITL escalation)
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import uuid4
from pydantic import BaseModel, Field


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class GatewayVerdict(str, Enum):
    PASS = "PASS"
    REPAIR = "REPAIR"
    BLOCK = "BLOCK"
    REVIEW = "REVIEW"


class ControlType(str, Enum):
    DETERMINISTIC = "deterministic"
    AI_SEMANTIC = "ai_semantic"
    SYSTEMIC = "systemic"


class ControlStage(str, Enum):
    BEFORE_CODING = "before_coding"
    DURING_WORK = "during_work"
    PRE_MERGE = "pre_merge"
    PRE_PROD_POST_DEPLOY = "pre_prod_post_deploy"


class RuleEnforcement(str, Enum):
    BLOCK = "block"
    REPAIR = "repair"
    REVIEW = "review"
    WARN = "warn"


class RuleSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class ModulePriority(str, Enum):
    P0 = "P0"
    P0_P1 = "P0/P1"
    P1 = "P1"
    P1_P2 = "P1/P2"
    P2 = "P2"


class RuleAppliesTo(BaseModel):
    languages: List[str] = Field(default_factory=lambda: ["python", "php", "typescript", "javascript"])
    components: List[str] = Field(default_factory=lambda: ["api", "backend", "frontend", "editor", "infra"])
    technologies: List[str] = Field(default_factory=list)


class RuleVerification(BaseModel):
    static_analysis: bool = True
    ai_review: bool = False
    integration_test: bool = False
    negative_test: bool = False
    systemic_check: bool = False


class AutofixSpec(BaseModel):
    enabled: bool = True
    require_revalidation: bool = True
    max_attempts: int = 3


class QualityRule(BaseModel):
    id: str
    version: str = "1.0.0"
    topic_number: Optional[int] = None
    name: str
    category: str
    module: str
    priority: ModulePriority = ModulePriority.P0
    severity: RuleSeverity = RuleSeverity.CRITICAL
    enforcement: RuleEnforcement = RuleEnforcement.BLOCK
    control_type: ControlType = ControlType.DETERMINISTIC
    stage: ControlStage = ControlStage.PRE_MERGE
    applies_to: RuleAppliesTo = Field(default_factory=RuleAppliesTo)
    triggers: List[str] = Field(default_factory=list)
    verification: RuleVerification = Field(default_factory=RuleVerification)
    requirements: List[str] = Field(default_factory=list)
    evidence_required: List[str] = Field(default_factory=list)
    autofix: AutofixSpec = Field(default_factory=AutofixSpec)
    scanner: str = "rae-security-gateway"


class EvidenceItem(BaseModel):
    rule_id: str
    source_location: Optional[str] = None
    affected_endpoint: Optional[str] = None
    authorization_path: Optional[str] = None
    test_result: Optional[str] = None
    scanner_output: Optional[str] = None
    data_flow_trace: Optional[str] = None
    approved_review_id: Optional[str] = None
    verified_by_tool: bool = False
    agent_statement: Optional[str] = None


class SecurityFinding(BaseModel):
    id: str = Field(default_factory=lambda: f"FND-{str(uuid4())[:8]}")
    rule_id: str
    rule_name: str
    module: str
    severity: RuleSeverity
    enforcement: RuleEnforcement
    control_type: ControlType
    scanner: str
    message: str
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    remediation: str
    evidence: Dict[str, Any] = Field(default_factory=dict)


class SARIFLocation(BaseModel):
    uri: str
    start_line: int = 1


class SARIFResult(BaseModel):
    ruleId: str
    level: str  # "error", "warning", "note"
    message: Dict[str, str]
    locations: List[Dict[str, Any]] = Field(default_factory=list)
    properties: Dict[str, Any] = Field(default_factory=dict)


class SARIFRun(BaseModel):
    tool: Dict[str, Any]
    results: List[SARIFResult] = Field(default_factory=list)
    invocations: List[Dict[str, Any]] = Field(default_factory=list)


class SARIFReport(BaseModel):
    version: str = "2.1.0"
    schema_uri: str = Field(
        default="https://json.schemastore.org/sarif-2.1.0.json",
        alias="$schema"
    )
    runs: List[SARIFRun] = Field(default_factory=list)
    rae_metadata: Dict[str, Any] = Field(default_factory=dict)


class MandatoryGateCheck(BaseModel):
    gate_id: str
    name: str
    verdict: GatewayVerdict
    blocking: bool = True
    details: str = ""
    rule_ids: List[str] = Field(default_factory=list)


class PRQualityAssessment(BaseModel):
    assessment_id: str = Field(default_factory=lambda: str(uuid4()))
    timestamp: datetime = Field(default_factory=_utc_now)
    verdict: GatewayVerdict
    merge_allowed: bool
    quality_score: int = Field(ge=0, le=100)
    tests_passed: int = 0
    tests_total: int = 0
    tests_failed: int = 0
    mandatory_gates: List[MandatoryGateCheck] = Field(default_factory=list)
    decision_summary: str
    findings: List[SecurityFinding] = Field(default_factory=list)
    audit_sha256: str = ""


class AutoRepairTask(BaseModel):
    repair_id: str = Field(default_factory=lambda: f"REP-{str(uuid4())[:8]}")
    change_id: str
    agent_id: str
    attempt: int = Field(ge=1)
    max_attempts: int = 3
    verdict: GatewayVerdict
    escalated_to_human: bool = False
    failed_rules: List[str] = Field(default_factory=list)
    minimal_fix_instructions: List[str] = Field(default_factory=list)
    independent_test_required: bool = True
    timestamp: datetime = Field(default_factory=_utc_now)


class AgentQualityScorecard(BaseModel):
    agent_id: str
    total_changes: int = 0
    total_defects: int = 0
    defects_per_change: float = 0.0
    first_time_fix_count: int = 0
    total_fix_attempts: int = 0
    first_time_fix_rate_pct: float = 100.0
    regressions_introduced: int = 0
    post_deploy_vulnerabilities: int = 0
    tamper_attempts_blocked: int = 0
    reliability_tier: str = "SOTA"
