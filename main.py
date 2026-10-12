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

import httpx

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("RAE-Quality")

from engines.governance.seniority_ranker import SeniorityRanker

class QualitySentinel:
    def __init__(self):
        self.enterprise_foundation = RAE_Enterprise_Foundation(module_name="rae-quality")
        self.tribunal = QualityTribunal()
        self.api_url = os.getenv("RAE_API_URL", "http://rae-api-dev:8000")

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
                            "issues": [issue.dict() for issue in result.issues],
                            "instruction": "URGENT: Fix the provided code based on the Tribunal's reasoning to pass the Quality Gate."
                        }
                    }, headers={"X-Tenant-Id": "system-governance", "X-Project-Id": project})
            except Exception as e:
                logger.error("enforcement_dispatch_failed", error=str(e))

    @audited_operation(operation_name="run_quality_audit", impact_level="medium")
    async def perform_static_audit(self, project_path: str):
        """Executes a full security and coverage audit for a given project."""
        sast = SastSecurityEngine(project_path)
        sast_report = await sast.run()
        
        testing = CoverageEngine(project_path)
        test_report = await testing.run()
        
        return f"Audit complete. Security Score: {sast_report.score}, Coverage Score: {test_report.score}"

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
        
        # Enforce minimum threshold (0.70)
        if score < 0.70:
            result.verdict = Verdict.REJECTED
            result.reasoning = (
                f"Code rejected by SenioritySentinel. Level classified as '{level}' (Score: {score}). "
                f"Complexity: {complexity}, Type Safety: {type_safety * 100:.1f}%. Minimum required score is 0.70."
            )
        
        # Faza 4: Aktywna Interwencja (Autonomia)
        asyncio.create_task(self._enforce_verdict(result, code, project))
        
        return result

# Inicjalizacja usług
from engines.testing.test_aggregator import UnifiedTestAggregator
from engines.testing.mutation_runner import MutationCoverageEngine

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

mcp_server = Server("rae-quality")

@mcp_server.list_tools()
async def handle_list_tools():
    return [
        Tool(
            name="run_static_quality_audit",
            description="Executes SAST and Coverage scans on a project path. Audited.",
            inputSchema={
                "type": "object",
                "properties": {
                    "project_path": {"type": "string"}
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
        )
    ]

@mcp_server.call_tool()
async def handle_call_tool(name: str, arguments: dict):
    if name == "run_static_quality_audit":
        path = arguments.get("project_path")
        result_text = await sentinel.perform_static_audit(path)
        return [TextContent(type="text", text=result_text)]
    
    if name == "run_tribunal_audit":
        code = arguments.get("code")
        project = arguments.get("project")
        importance = arguments.get("importance", "medium")
        result = await sentinel.perform_tribunal_audit(code, project, importance)
        return [TextContent(type="text", text=result.json())]

    if name == "get_risk_coverage":
        if arguments.get("run_live_verification", True):
            risk_engine.run_automated_live_verification()
        coverage = risk_engine.calculate_risk_coverage()
        return [TextContent(type="text", text=coverage.json())]

    if name == "evaluate_deployment_gate":
        risk_engine.run_automated_live_verification()
        gate = risk_engine.evaluate_deployment_gate()
        return [TextContent(type="text", text=gate.json())]

    if name == "run_pdf_dtp_audit":
        doc_spec = arguments.get("doc_spec", {})
        res = pdf_validator.audit_document(doc_spec)
        return [TextContent(type="text", text=res.json())]

    if name == "run_calculator_audit":
        res = calc_verifier.run_full_suite()
        import json
        return [TextContent(type="text", text=json.dumps(res, indent=2))]

    if name == "run_golden_set_dtp_audit":
        res = golden_set_runner.run_golden_set_regression()
        import json
        return [TextContent(type="text", text=json.dumps(res, indent=2))]

    if name == "run_sonarqube_security_audit":
        res = sonar_client.get_aggregate_security_score()
        import json
        return [TextContent(type="text", text=json.dumps(res, indent=2))]

    if name == "get_sonar_strict_metrics":
        res = sonar_client.get_aggregate_security_score()
        import json
        return [TextContent(type="text", text=json.dumps(res.get("strict_measures", []), indent=2))]

    if name == "get_unit_test_inventory":
        res = test_aggregator.run_full_inventory()
        import json
        return [TextContent(type="text", text=json.dumps(res, indent=2))]

    if name == "run_mutation_audit":
        res = mutation_engine.run_full_mutation_audit()
        import json
        return [TextContent(type="text", text=json.dumps(res, indent=2))]

    if name == "get_predictive_test_plan":
        files = arguments.get("modified_files", [])
        res = risk_engine.get_predictive_test_plan(files)
        import json
        return [TextContent(type="text", text=json.dumps(res, indent=2))]
        
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

@app.get("/health")
def health():
    return {"status": "healthy"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
