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
from models.report import AuditResult, Verdict

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
sentinel = QualitySentinel()
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
        
    raise ValueError(f"Unknown tool: {name}")

app = FastAPI()
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

@app.get("/health")
def health():
    return {"status": "healthy"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
