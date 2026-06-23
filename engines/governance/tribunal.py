# engines/governance/tribunal.py
import asyncio
import os
import httpx
import logging
from typing import Dict, Any, Optional
from models.report import AuditResult, Verdict, QualityIssue, Severity

logger = logging.getLogger("RAE-Quality.Tribunal")

class QualityTribunal:
    """Advanced 3-Tier Quality Tribunal for Silicon Oracle RAE Suite."""
    
    def __init__(self, rae_api_url: Optional[str] = None):
        self.api_url = rae_api_url or os.getenv("RAE_API_URL", "http://rae-api-dev:8000")
        self.timeout = httpx.Timeout(120.0, connect=10.0)
        self.tier2_agent = os.getenv("TRIBUNAL_TIER2_AGENT", "rae-local-reasoner")
        self.tier3_agent = os.getenv("TRIBUNAL_TIER3_AGENT", "rae-oracle-gemini")

    async def run_audit(self, code: str, project: str, importance: str = "medium") -> AuditResult:
        """Executes the full 3-tier audit pipeline."""
        logger.info(f"tribunal_audit_started: project={project}, importance={importance}")
        
        # --- TIER 1: Deterministic Guards ---
        t1_result = self._run_tier1_checks(code)
        if t1_result.verdict == Verdict.REJECTED:
            return t1_result

        # --- TIER 2: Local Semantic Consensus (Context-Aware) ---
        t2_result = await self._run_tier2_consensus(code, project)
        if t2_result.verdict == Verdict.REJECTED or importance != "critical":
            return t2_result

        # --- TIER 3: Supreme Court (SaaS Escalation via Bridge) ---
        return await self._run_tier3_escalation(code, project, t2_result)

    def _run_tier1_checks(self, code: str) -> AuditResult:
        """Fast, static, and deterministic checks."""
        issues = []
        if "TODO" in code.upper() or "FIXME" in code.upper():
            issues.append(QualityIssue(engine="Tier1", severity=Severity.MEDIUM, message="Code contains pending placeholders (TODO/FIXME)."))
        
        if len(code) < 10:
            issues.append(QualityIssue(engine="Tier1", severity=Severity.LOW, message="Code snippet is suspiciously short."))

        if issues:
            return AuditResult(verdict=Verdict.REJECTED, confidence=1.0, score=0.0, issues=issues, reasoning="Failed Tier 1 static guards.", tier_reached=1)
        
        return AuditResult(verdict=Verdict.PASSED, confidence=1.0, score=1.0, reasoning="Passed Tier 1 static guards.", tier_reached=1)

    async def _run_tier2_consensus(self, code: str, project: str) -> AuditResult:
        """Semantic review using Local LLM with Memory Context."""
        try:
            # 1. Fetch guidelines from RAE Memory (Semantic Layer)
            guidelines = await self._fetch_project_guidelines(project)
            
            # 2. Construct Prompt for Local LLM (Ollama via Bridge or Direct)
            prompt = f"""
            SYSTEM: You are the RAE Tier 2 Quality Auditor.
            PROJECT CONTEXT: {guidelines}
            CODE TO AUDIT:
            ```
            {code}
            ```
            TASK: Evaluate for SOLID principles, readability, and context compliance.
            Respond ONLY in JSON: {{"verdict": "PASSED"|"REJECTED", "score": 0.0-1.0, "reasoning": "string"}}
            """
            
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                # Wywołanie lokalnej inferencji przez Mostek A2A
                resp = await client.post(f"{self.api_url}/v2/bridge/interact", json={
                    "intent": "LOCAL_LLM_AUDIT",
                    "target_agent": self.tier2_agent,
                    "payload": {"prompt": prompt}
                })
                
                if resp.status_code == 200:
                    data = resp.json().get("payload", {}).get("interaction_data", {})
                    # Tu powinna być walidacja JSON, dla uproszczenia zakładamy poprawność formatu
                    return AuditResult(
                        verdict=Verdict.PASSED if data.get("verdict") == "PASSED" else Verdict.REJECTED,
                        confidence=0.85,
                        score=data.get("score", 0.5),
                        reasoning=data.get("reasoning", "Semantic consensus reached."),
                        tier_reached=2
                    )
                
                return AuditResult(verdict=Verdict.ERROR, confidence=0.0, score=0.0, reasoning="Local consensus failed (network/api error).", tier_reached=2)
        except Exception as e:
            logger.error("tier2_failed", error=str(e))
            return AuditResult(verdict=Verdict.ERROR, confidence=0.0, score=0.0, reasoning=f"Tier 2 Exception: {str(e)}", tier_reached=2)

    async def _run_tier3_escalation(self, code: str, project: str, t2_result: AuditResult) -> AuditResult:
        """High-level reasoning using SaaS Models (Gemini/GPT-4) via Bridge."""
        logger.warning(f"tier3_escalation_initiated: project={project}")
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.post(f"{self.api_url}/v2/bridge/interact", json={
                    "intent": "SUPREME_COURT_AUDIT",
                    "target_agent": self.tier3_agent,
                    "payload": {
                        "code": code,
                        "project": project,
                        "previous_reasoning": t2_result.reasoning
                    }
                })
                
                if resp.status_code == 200:
                    data = resp.json().get("payload", {}).get("interaction_data", {})
                    return AuditResult(
                        verdict=Verdict.PASSED if data.get("verdict") == "PASSED" else Verdict.REJECTED,
                        confidence=0.98,
                        score=data.get("score", 1.0),
                        reasoning=f"Supreme Court Verdict: {data.get('reasoning')}",
                        tier_reached=3,
                        metadata={"consensus_log": data.get("detailed_audit")}
                    )
            return AuditResult(verdict=Verdict.ERROR, confidence=0.0, score=0.0, reasoning="Supreme Court inaccessible.", tier_reached=3)
        except Exception as e:
            return AuditResult(verdict=Verdict.ERROR, confidence=0.0, score=0.0, reasoning=f"Tier 3 Exception: {str(e)}", tier_reached=3)

    async def _fetch_project_guidelines(self, project: str) -> str:
        """Retrieves project-specific coding standards from RAE Memory."""
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.post(f"{self.api_url}/v2/memories/query", json={
                    "query": "coding standards and architectural guidelines",
                    "project": project,
                    "k": 3
                })
                if resp.status_code == 200:
                    results = resp.json().get("results", [])
                    return " ".join([r.get("content", "") for r in results])
            return "General best practices."
        except:
            return "General best practices."
