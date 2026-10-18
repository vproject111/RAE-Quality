# main.py
import asyncio
import logging
import ast
import os
import sys

# Enforce Git Flow & SemVer Branch Guard Validation
try:
    from rae_core.governance.versioning import VersioningValidator
    VersioningValidator(
        project_path=os.path.dirname(os.path.abspath(__file__)),
        module_name="rae-quality",
        config={"strategy": "git-flow", "strict": True}
    ).validate()
except Exception as e:
    print(f"❌ Git Flow Validation failed: {e}", file=sys.stderr)
    sys.exit(1)

from fastapi import FastAPI, Request
from mcp.server import Server
from mcp.types import Tool, TextContent
from mcp.server.sse import SseServerTransport
from engines.security.sast import SastSecurityEngine
from engines.testing.coverage import CoverageEngine
from engines.testing.ast_inspector import ASTInspector
from engines.governance.tribunal import QualityTribunal
from engines.governance.risk_coverage_engine import RiskCoverageEngine
from engines.governance.defect_tracker import DefectTracker
from engines.testing.pdf_dtp_validator import PDFDtpValidator
from engines.testing.golden_set_runner import GoldenSetRunner
from engines.testing.calculator_verifier import CalculatorVerifier
from engines.security.sonar_client import SonarQubeClient
from models.report import AuditResult, Verdict
from models.risk import RiskSeverity

# Import Bridge Handler
try:
    from rae_libs.rae_core.bridge.handler import register_bridge
    from rae_libs.rae_core.utils.enterprise_guard import RAE_Enterprise_Foundation, audited_operation
except ImportError:
    from rae_core.bridge.handler import register_bridge
    from rae_core.utils.enterprise_guard import RAE_Enterprise_Foundation, audited_operation

# Import TestIntegrityGuard
from src.test_integrity_guard import TestIntegrityGuard

import httpx

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("RAE-Quality")

from engines.governance.seniority_ranker import SeniorityRanker

class QualitySentinel:
    def __init__(self):
        self.enterprise_foundation = RAE_Enterprise_Foundation(module_name="rae-quality")
        self.tribunal = QualityTribunal()
        self.test_guard = TestIntegrityGuard()
        self.api_url = os.getenv("RAE_API_URL", "http://rae-api-dev:8000")
        
        # Quality baseline defaults
        self.baseline_coverage = 80.0
        self.baseline_vulnerabilities = 0

    async def _enforce_verdict(self, result: AuditResult, code: str, project: str):
        """Autonomously triggers Phoenix repair if code is rejected."""
        if result.verdict == Verdict.REJECTED:
            logger.warning("enforcement_triggered", reason="Code rejected by Tribunal. Waking up Phoenix.")
            try:
                async with httpx.AsyncClient(timeout=30.0) as client:
                    await client.post(f"{self.api_url}/v2/bridge/interact", json={
                        "intent": "REFACTOR_CODE",
                        "source_agent": "rae-quality",
                        "target_agent": "rae-phoenix",
                        "payload": {
                            "project": project,
                            "faulty_code": code,
                            "tribunal_reasoning": result.reasoning,
                            "issues": [issue.model_dump() for issue in result.issues],
                            "instruction": "URGENT: Fix the provided code based on the Tribunal's reasoning to pass the Quality Gate."
                        }
                    }, headers={"X-Tenant-Id": "system-governance", "X-Project-Id": project})
            except Exception as e:
                logger.error("enforcement_dispatch_failed", error=str(e))

    @audited_operation(operation_name="run_quality_audit", impact_level="medium")
    async def perform_static_audit(self, project_path: str, baseline_code: str = None, proposed_code: str = None) -> str:
        """
        Executes a full security and coverage audit, enforcing baseline and test integrity checks.
        """
        # 1. Run SAST Security Engine
        sast = SastSecurityEngine(project_path)
        sast_report = await sast.run()
        
        # 2. Run Coverage Engine
        testing = CoverageEngine(project_path)
        test_report = await testing.run()
        
        # 3. Check Quality Baseline Regression
        rejection_reasons = []
        
        if test_report.score < self.baseline_coverage:
            rejection_reasons.append(f"Test coverage ({test_report.score}%) dropped below baseline ({self.baseline_coverage}%).")
            
        if sast_report.critical_count > self.baseline_vulnerabilities:
            rejection_reasons.append(f"Vulnerability count ({sast_report.critical_count}) exceeds baseline ({self.baseline_vulnerabilities}).")

        # 4. Enforce TestIntegrityGuard if test modification is proposed
        if baseline_code and proposed_code:
            passed, reason = self.test_guard.validate_test_integrity(baseline_code, proposed_code)
            if not passed:
                rejection_reasons.append(reason)

        if rejection_reasons:
            rejection_summary = " | ".join(rejection_reasons)
            logger.warning(f"Quality Gate REJECT: {rejection_summary}")
            return f"REJECTED. Reason: {rejection_summary}"
            
        return f"ACCEPTED. Security Score: {sast_report.score}, Coverage Score: {test_report.score}"

    @audited_operation(operation_name="run_tribunal_audit", impact_level="high")
    async def perform_tribunal_audit(self, code: str, project: str, importance: str = "medium") -> AuditResult:
        """Executes the advanced 3-tier tribunal audit and enforces policy."""
        # 1. Deterministic AST Inspection (sub-20ms)
        ast_metrics = ASTInspector.analyze_code(code)
        if not ast_metrics["is_valid_syntax"]:
            result = AuditResult(
                verdict=Verdict.REJECTED,
                score=0.0,
                confidence=1.0,
                reasoning=f"AST parse failed: {ast_metrics.get('syntax_error')}",
                issues=ast_metrics["issues"],
                seniority_level="junior"
            )
            asyncio.create_task(self._enforce_verdict(result, code, project))
            return result

        # 2. Standard tribunal scan (heuristics / semantic consensus)
        result = await self.tribunal.run_audit(code, project, importance)
        result.issues.extend(ast_metrics["issues"])

        # 2b. Enrich with RAE-Quality 2.0 Security & Architecture Engines
        try:
            from engines.governance.security_scanner_engine import SecurityScannerEngine
            from engines.governance.architecture_guard_engine import ArchitectureGuardEngine
            from models.report import CodeIssue
            sec_scan = SecurityScannerEngine().scan({"code": code, "file_path": "audit_target.py"})
            arch_scan = ArchitectureGuardEngine().check_architecture({"code": code, "file_path": "audit_target.py"})
            for f in sec_scan.get("findings", []):
                if f.get("severity") in ("CRITICAL", "HIGH"):
                    result.issues.append(CodeIssue(
                        line=f.get("line", 1),
                        column=1,
                        severity=RiskSeverity.CRITICAL if f.get("severity") == "CRITICAL" else RiskSeverity.HIGH,
                        code=f.get("rule_id", "SEC-V2"),
                        message=f.get("message", "Security violation detected by RAE-Quality 2.0"),
                        category="security"
                    ))
            for v in arch_scan.get("violations", []):
                if v.get("severity") in ("CRITICAL", "HIGH"):
                    result.issues.append(CodeIssue(
                        line=v.get("line", 1),
                        column=1,
                        severity=RiskSeverity.HIGH,
                        code=v.get("rule_id", "ARCH-V2"),
                        message=v.get("message", "Architecture violation detected by RAE-Quality 2.0"),
                        category="architecture"
                    ))
        except Exception as e:
            logger.debug(f"RAE-Quality 2.0 enrichment skipped: {e}")
        
        # 3. Calculate dynamic Seniority Rank from real AST measurements
        complexity = float(ast_metrics["complexity"])
        type_safety = float(ast_metrics["type_safety"])
        coverage = getattr(result, "coverage", 0.90)
        
        score = SeniorityRanker.calculate_score(coverage, complexity, type_safety)
        level = SeniorityRanker.classify_level(score)
        
        result.score = score
        result.seniority_level = level.lower().replace(" ", "_")
        result.metadata = result.metadata or {}
        result.metadata["seniority_level"] = level
        result.metadata["ast_complexity"] = complexity
        result.metadata["ast_type_safety"] = type_safety
        
        # Enforce minimum threshold (0.70) and zero critical security issues
        has_critical_sec = any(
            getattr(i, "severity", None) == RiskSeverity.CRITICAL and getattr(i, "category", "") == "security"
            for i in result.issues
        )
        if score < 0.70 or has_critical_sec:
            result.verdict = Verdict.REJECTED
            result.reasoning = (
                f"Code rejected by SenioritySentinel. Level classified as '{level}' (Score: {score}). "
                f"Complexity: {complexity}, Type Safety: {type_safety * 100:.1f}%, CriticalSecurity: {has_critical_sec}. Minimum required score is 0.70."
            )
        
        # Faza 4: Aktywna Interwencja (Autonomia) / Enforce active Phoenix intervention
        asyncio.create_task(self._enforce_verdict(result, code, project))
        
        return result

# Inicjalizacja usług
import json
from engines.testing.test_aggregator import UnifiedTestAggregator
from engines.testing.mutation_runner import MutationCoverageEngine
from engines.governance.quality_gateway_v2 import RAEQualityGatewayV2

sentinel = QualitySentinel()
defect_tracker = DefectTracker()
pdf_validator = PDFDtpValidator()
golden_set_runner = GoldenSetRunner(pdf_validator)
calc_verifier = CalculatorVerifier()
sonar_client = SonarQubeClient()
test_aggregator = UnifiedTestAggregator()
mutation_engine = MutationCoverageEngine()

risk_engine = RiskCoverageEngine(
    calculator_verifier=calc_verifier,
    pdf_validator=pdf_validator,
    sonar_client=sonar_client,
    golden_set_runner=golden_set_runner,
    test_aggregator=test_aggregator,
    mutation_engine=mutation_engine
)

quality_gateway_v2 = RAEQualityGatewayV2(
    risk_engine=risk_engine,
    defect_tracker=defect_tracker,
)

mcp_server = Server("rae-quality")

@mcp_server.list_tools()
async def handle_list_tools():
    return [
        Tool(
            name="run_static_quality_audit",
            description="Executes SAST and Coverage scans, enforcing Quality Baseline and TestIntegrity checks. Audited.",
            inputSchema={
                "type": "object",
                "properties": {
                    "project_path": {"type": "string"},
                    "baseline_code": {"type": "string", "description": "Original test code before modifications"},
                    "proposed_code": {"type": "string", "description": "New proposed test code to evaluate"}
                },
                "required": ["project_path"]
            }
        ),
        Tool(
            name="run_tribunal_audit",
            description="Executes the 3-Tier Quality Tribunal (Semantic + LLM) on a code snippet. High impact.",
            inputSchema={
                "type": "object",
                "properties": {
                    "code": {"type": "string"},
                    "project": {"type": "string"},
                    "importance": {"type": "string", "enum": ["low", "medium", "critical"]}
                },
                "required": ["code", "project"]
            }
        ),
        Tool(
            name="get_risk_coverage",
            description="Calculates weighted risk coverage across Dreamsoft and RAE-Suite critical business paths.",
            inputSchema={
                "type": "object",
                "properties": {
                    "run_live_verification": {"type": "boolean", "default": True}
                }
            }
        ),
        Tool(
            name="evaluate_deployment_gate",
            description="Evaluates the 3-level deployment decision (Level 1: Approved, Level 2: Warning, Level 3: Blocked).",
            inputSchema={"type": "object", "properties": {}}
        ),
        Tool(
            name="run_pdf_dtp_audit",
            description="Audits DTP PDF production specifications: TrimBox, BleedBox, pure K typography, and Spot Colors.",
            inputSchema={
                "type": "object",
                "properties": {
                    "doc_spec": {"type": "object"}
                },
                "required": ["doc_spec"]
            }
        ),
        Tool(
            name="run_calculator_audit",
            description="Validates pricing calculation monotonicity, format proportionality, and p95 latency SLA.",
            inputSchema={"type": "object", "properties": {}}
        ),
        Tool(
            name="run_golden_set_dtp_audit",
            description="Audits the canonical Golden Set of 5 print products for DTP regression.",
            inputSchema={"type": "object", "properties": {}}
        ),
        Tool(
            name="run_sonarqube_security_audit",
            description="Executes live SonarQube Quality Gate checks across all 5 core projects.",
            inputSchema={"type": "object", "properties": {}}
        ),
        Tool(
            name="get_predictive_test_plan",
            description="Recommends prioritized test paths based on modified files and RAE-Phoenix impact zone.",
            inputSchema={
                "type": "object",
                "properties": {
                    "modified_files": {
                        "type": "array",
                        "items": {"type": "string"}
                    }
                },
                "required": ["modified_files"]
            }
        ),
        Tool(
            name="get_sonar_strict_metrics",
            description="Audits 6 strict SonarQube Rating A metrics (vulnerabilities:0, bugs:0, smells:0, hotspots:100%, coverage:>90%, duplications:0%) across core projects.",
            inputSchema={"type": "object", "properties": {}}
        ),
        Tool(
            name="get_unit_test_inventory",
            description="Verifies dual volume requirements: >= 1000 unit tests in RAE-Suite and >= 1000 in Dreamsoft Factory.",
            inputSchema={"type": "object", "properties": {}}
        ),
        Tool(
            name="run_mutation_audit",
            description="Audits mutation testing resilience and enforces MSI >= 90% across Stryker, Infection, and Mutmut.",
            inputSchema={"type": "object", "properties": {}}
        ),
        # RAE-Quality 2.0 Canonical 8 Agent Operations (Section 6)
        Tool(
            name="quality.get_policy",
            description="Pobiera wymagania bezpieczeństwa przed rozpoczęciem zadania (Stage 1: Before Coding).",
            inputSchema={
                "type": "object",
                "properties": {
                    "task_description": {"type": "string"},
                    "modified_files": {"type": "array", "items": {"type": "string"}},
                    "technologies": {"type": "array", "items": {"type": "string"}}
                }
            }
        ),
        Tool(
            name="quality.analyze_diff",
            description="Analizuje zmieniane pliki podczas pracy agenta (Stage 2: During Work).",
            inputSchema={
                "type": "object",
                "properties": {
                    "diff": {"type": "string"},
                    "modified_files": {"type": "array", "items": {"type": "string"}},
                    "agent_id": {"type": "string"},
                    "change_id": {"type": "string"}
                }
            }
        ),
        Tool(
            name="quality.security_scan",
            description="Uruchamia skanery bezpieczeństwa i zwraca raport SARIF 2.1.0.",
            inputSchema={
                "type": "object",
                "properties": {
                    "code": {"type": "string"},
                    "file_path": {"type": "string"},
                    "languages": {"type": "array", "items": {"type": "string"}}
                }
            }
        ),
        Tool(
            name="quality.generate_tests",
            description="Proponuje testy negatywne, izolacji tenantów i regresyjne.",
            inputSchema={
                "type": "object",
                "properties": {
                    "target_endpoint": {"type": "string"},
                    "component": {"type": "string"},
                    "rule_ids": {"type": "array", "items": {"type": "string"}}
                }
            }
        ),
        Tool(
            name="quality.verify_fix",
            description="Potwierdza usunięcie podatności na czystym zestawie testów (blokuje manipulację testami).",
            inputSchema={
                "type": "object",
                "properties": {
                    "original_code": {"type": "string"},
                    "fixed_code": {"type": "string"},
                    "rule_id": {"type": "string"},
                    "canonical_test_code": {"type": "string"},
                    "agent_submitted_test_code": {"type": "string"}
                },
                "required": ["original_code", "fixed_code", "rule_id"]
            }
        ),
        Tool(
            name="quality.check_architecture",
            description="Sprawdza zgodność z architekturą, bazą danych, transakcjami, współbieżnością i OpenAPI.",
            inputSchema={
                "type": "object",
                "properties": {
                    "code": {"type": "string"},
                    "file_path": {"type": "string"},
                    "technologies": {"type": "array", "items": {"type": "string"}},
                    "openapi_before": {"type": "object"},
                    "openapi_after": {"type": "object"}
                }
            }
        ),
        Tool(
            name="quality.release_gate",
            description="Zwraca decyzję o dopuszczeniu zmiany (Quality Score 0-100 + Mandatory Gates: PASS/REPAIR/BLOCK).",
            inputSchema={
                "type": "object",
                "properties": {
                    "code": {"type": "string"},
                    "file_path": {"type": "string"},
                    "tests_passed": {"type": "integer"},
                    "tests_total": {"type": "integer"}
                }
            }
        ),
        Tool(
            name="quality.report",
            description="Generuje pełny raport jakości, manifest 219 reguł, kryteria akceptacji i historię audytową.",
            inputSchema={"type": "object", "properties": {}}
        )
    ]

@mcp_server.call_tool()
async def handle_call_tool(name: str, arguments: dict):
    if name == "run_static_quality_audit":
        path = arguments.get("project_path")
        baseline = arguments.get("baseline_code")
        proposed = arguments.get("proposed_code")
        result_text = await sentinel.perform_static_audit(path, baseline, proposed)
        return [TextContent(type="text", text=result_text)]
    
    if name == "run_tribunal_audit":
        code = arguments.get("code")
        project = arguments.get("project")
        importance = arguments.get("importance", "medium")
        result = await sentinel.perform_tribunal_audit(code, project, importance)
        return [TextContent(type="text", text=result.model_dump_json())]

    if name == "get_risk_coverage":
        if arguments.get("run_live_verification", True):
            risk_engine.run_automated_live_verification()
        coverage = risk_engine.calculate_risk_coverage()
        return [TextContent(type="text", text=coverage.model_dump_json())]

    if name == "evaluate_deployment_gate":
        risk_engine.run_automated_live_verification()
        gate = risk_engine.evaluate_deployment_gate()
        return [TextContent(type="text", text=gate.model_dump_json())]

    if name == "run_pdf_dtp_audit":
        doc_spec = arguments.get("doc_spec", {})
        res = pdf_validator.audit_document(doc_spec)
        return [TextContent(type="text", text=res.model_dump_json())]

    if name == "run_calculator_audit":
        res = calc_verifier.run_full_suite()
        return [TextContent(type="text", text=json.dumps(res, indent=2))]

    if name == "run_golden_set_dtp_audit":
        res = golden_set_runner.run_golden_set_regression()
        return [TextContent(type="text", text=json.dumps(res, indent=2))]

    if name == "run_sonarqube_security_audit":
        res = sonar_client.get_aggregate_security_score()
        return [TextContent(type="text", text=json.dumps(res, indent=2))]

    if name == "get_sonar_strict_metrics":
        res = sonar_client.get_aggregate_security_score()
        return [TextContent(type="text", text=json.dumps(res.get("strict_measures", []), indent=2))]

    if name == "get_unit_test_inventory":
        res = test_aggregator.run_full_inventory()
        return [TextContent(type="text", text=json.dumps(res, indent=2))]

    if name == "run_mutation_audit":
        res = mutation_engine.run_full_mutation_audit()
        return [TextContent(type="text", text=json.dumps(res, indent=2))]

    if name == "get_predictive_test_plan":
        files = arguments.get("modified_files", [])
        res = risk_engine.get_predictive_test_plan(files)
        return [TextContent(type="text", text=json.dumps(res, indent=2))]

    normalized_op = name.replace("quality_", "quality.") if name.startswith("quality_") else name
    if normalized_op.startswith("quality."):
        res = quality_gateway_v2.dispatch_rpc(normalized_op, arguments)
        return [TextContent(type="text", text=json.dumps(res, indent=2, default=str))]
        
    raise ValueError(f"Unknown tool: {name}")

app = FastAPI(title="RAE-Quality Service", version="2.9.0")
register_bridge(app, "rae-quality")
sse = SseServerTransport("/mcp/messages")

@app.get("/mcp/sse")
async def mcp_sse_endpoint(request: Request):
    async with sse.connect_sse(request.scope, request.receive, request._send) as (read_stream, write_stream):
        await mcp_server.run(read_stream, write_stream, mcp_server.create_initialization_options())

@app.post("/mcp/messages")
async def mcp_messages_endpoint(request: Request):
    await sse.handle_post_message(request.scope, request.receive, request._send)

@app.post("/v2/quality/audit")
async def api_tribunal_audit(payload: dict):
    """External API endpoint for RAE Suite to request semantic audits."""
    code = payload.get("code")
    project = payload.get("project")
    importance = payload.get("importance", "medium")
    return await sentinel.perform_tribunal_audit(code, project, importance)

@app.get("/v2/quality/risk-coverage")
async def api_get_risk_coverage():
    """Returns the current weighted Risk Coverage across all critical business paths."""
    return risk_engine.calculate_risk_coverage()

@app.post("/v2/quality/risk-coverage/verify")
async def api_verify_risk_coverage():
    """Executes live automated verifications and recalculates Risk Coverage."""
    run_details = risk_engine.run_automated_live_verification()
    coverage = risk_engine.calculate_risk_coverage()
    return {"coverage": coverage, "execution_details": run_details}

@app.get("/v2/quality/gate-decision")
async def api_get_gate_decision():
    """Evaluates the 3-level deployment decision (Level 1: Approved, Level 2: Warning, Level 3: Blocked)."""
    return risk_engine.evaluate_deployment_gate()

@app.post("/v2/quality/dtp-audit")
async def api_dtp_audit(payload: dict):
    """Audits PDF DTP specifications for TrimBox, BleedBox, pure black text, and spot layers."""
    return pdf_validator.audit_document(payload)

@app.post("/v2/quality/calculator-audit")
async def api_calculator_audit():
    """Runs price monotonicity, format proportionality, and latency SLA checks."""
    return calc_verifier.run_full_suite()

@app.get("/v2/quality/defect-metrics")
async def api_get_defect_metrics():
    """Returns Defect Escape Rate, Severity-Weighted score, and MTTR."""
    return defect_tracker.calculate_metrics()

@app.get("/v2/quality/golden-set-audit")
async def api_get_golden_set_audit():
    """Audits the canonical Golden Set of 5 print products for DTP regression."""
    return golden_set_runner.run_golden_set_regression()

@app.get("/v2/quality/sonarqube-audit")
async def api_get_sonarqube_audit():
    """Executes live SonarQube Quality Gate checks across core projects."""
    return sonar_client.get_aggregate_security_score()

@app.post("/v2/quality/predictive-plan")
async def api_get_predictive_plan(payload: dict):
    """Recommends prioritized test paths based on modified files and RAE-Phoenix impact zone."""
    files = payload.get("modified_files", [])
    return risk_engine.get_predictive_test_plan(files)

@app.get("/v2/quality/sonar-strict-metrics")
async def api_get_sonar_strict_metrics():
    """Audits 6 strict SonarQube Rating A metrics across all core projects."""
    res = sonar_client.get_aggregate_security_score()
    return res.get("strict_measures", [])

@app.get("/v2/quality/unit-test-inventory")
async def api_get_unit_test_inventory():
    """Verifies dual volume requirements: >= 1000 unit tests in RAE-Suite and >= 1000 in Dreamsoft Factory."""
    return test_aggregator.run_full_inventory()

@app.get("/v2/quality/mutation-audit")
async def api_get_mutation_audit():
    """Audits mutation testing resilience and enforces MSI >= 90% across Stryker, Infection, and Mutmut."""
    return mutation_engine.run_full_mutation_audit()

# --- RAE-Quality 2.0 Endpoints (8 Operations + RPC + Manifest) ---

@app.post("/v2/quality/policy")
async def api_quality_get_policy(payload: dict):
    """Stage 1 (quality.get_policy): Returns security & architecture rules tailored to task risk profile."""
    return quality_gateway_v2.get_policy(payload)

@app.post("/v2/quality/analyze-diff")
async def api_quality_analyze_diff(payload: dict):
    """Stage 2 (quality.analyze_diff): Analyzes in-flight code diffs and schedules surgical auto-repair if needed."""
    return quality_gateway_v2.analyze_diff(payload)

@app.post("/v2/quality/security-scan")
async def api_quality_security_scan(payload: dict):
    """Stage 3 (quality.security_scan): Runs SAST/Secrets/Auth/Editor security scans with SARIF 2.1.0 output."""
    return quality_gateway_v2.security_scan(payload)

@app.post("/v2/quality/generate-tests")
async def api_quality_generate_tests(payload: dict):
    """Stage 3 (quality.generate_tests): Generates negative, tenant-isolation, and regression tests."""
    return quality_gateway_v2.generate_tests(payload)

@app.post("/v2/quality/verify-fix")
async def api_quality_verify_fix(payload: dict):
    """Stage 3 (quality.verify_fix): Independently verifies fixes and blocks test tampering."""
    return quality_gateway_v2.verify_fix(payload)

@app.post("/v2/quality/check-architecture")
async def api_quality_check_architecture(payload: dict):
    """Stage 3 (quality.check_architecture): Verifies DB migrations, transactions, N+1, concurrency, and OpenAPI."""
    return quality_gateway_v2.check_architecture(payload)

@app.post("/v2/quality/release-gate")
async def api_quality_release_gate(payload: dict):
    """Stage 4 (quality.release_gate): Evaluates Dual Risk Assessment (Quality Score 0-100 + Mandatory Gates)."""
    return quality_gateway_v2.release_gate(payload)

@app.get("/v2/quality/report")
async def api_quality_report():
    """Stage 4 (quality.report): Returns full RAE-Quality 2.0 report, 9/9 acceptance criteria, and audit trail."""
    return quality_gateway_v2.report()

@app.get("/v2/quality/manifest")
async def api_quality_manifest():
    """Returns the technical manifest of all 219 rules (198 catalog + 12 AI/SaaS + 9 RAE-EDITOR-SECURITY)."""
    return quality_gateway_v2.policy_engine.generate_technical_manifest()

@app.post("/v2/quality/rpc")
async def api_quality_rpc(payload: dict):
    """Unified RPC endpoint for `quality.<operation>` invocations."""
    operation = payload.get("operation", "")
    params = payload.get("params", {})
    return quality_gateway_v2.dispatch_rpc(operation, params)

@app.get("/health")
def health():
    return {"status": "healthy"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
