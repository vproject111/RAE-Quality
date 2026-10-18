# packages/rae-quality/engines/governance/auto_repair.py
"""
RAE-Quality 2.0 Auto-Repair Loop (Max 3 Attempts), Agent Scorecard & Immutable Audit Trail.
Implements Sections 8, 9, 11, and 12 of docs/poziom-bezpieczeństwa-kodu.md:
- Max 3 auto-repair cycles per change; escalates to Human Review (HITL) after 3 failures
- Per-agent quality metrics (defects/change, first-time fix rate, regressions, escaped vulns)
- Cryptographic SHA-256 hash-chained audit trail (RAE-SEC-210)
"""

import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from models.security_v2 import (
    AgentQualityScorecard,
    AutoRepairTask,
    GatewayVerdict,
)


class AutoRepairOrchestrator:
    """
    Manages the automated repair cycle for AI agents (Section 9):
    - Max 3 attempts (`MAX_ATTEMPTS = 3`)
    - Minimal surgical fix instructions without scope creep
    - Automatic escalation to Human Review after 3 failed repair attempts
    """

    MAX_ATTEMPTS = 3

    def __init__(self):
        self._attempts_by_change: Dict[str, int] = {}
        self._history: List[AutoRepairTask] = []

    def evaluate_or_schedule_repair(
        self,
        change_id: str,
        agent_id: str,
        findings: List[Dict[str, Any]],
    ) -> AutoRepairTask:
        if not findings:
            task = AutoRepairTask(
                change_id=change_id,
                agent_id=agent_id,
                attempt=max(1, self._attempts_by_change.get(change_id, 1)),
                max_attempts=self.MAX_ATTEMPTS,
                verdict=GatewayVerdict.PASS,
                escalated_to_human=False,
                failed_rules=[],
                minimal_fix_instructions=["All checks passed. Merge permitted."],
            )
            self._history.append(task)
            return task

        current_attempt = self._attempts_by_change.get(change_id, 0) + 1
        self._attempts_by_change[change_id] = current_attempt

        failed_rules = sorted(list({f.get("rule_id", "UNKNOWN") for f in findings}))
        instructions = [
            f"[{f.get('rule_id')}] {f.get('remediation', f.get('message', 'Fix issue'))} (Surgical fix only, do not alter unrelated code or tests)"
            for f in findings
        ]

        if current_attempt > self.MAX_ATTEMPTS:
            # Exceeded 3 auto-repair attempts -> Escalate to Human Review & BLOCK
            task = AutoRepairTask(
                change_id=change_id,
                agent_id=agent_id,
                attempt=current_attempt,
                max_attempts=self.MAX_ATTEMPTS,
                verdict=GatewayVerdict.BLOCK,
                escalated_to_human=True,
                failed_rules=failed_rules,
                minimal_fix_instructions=[
                    f"ESCALATED TO HUMAN REVIEW: Auto-repair exhausted maximum {self.MAX_ATTEMPTS} attempts. "
                    "Manual security architecture review required."
                ] + instructions,
            )
        else:
            task = AutoRepairTask(
                change_id=change_id,
                agent_id=agent_id,
                attempt=current_attempt,
                max_attempts=self.MAX_ATTEMPTS,
                verdict=GatewayVerdict.REPAIR,
                escalated_to_human=False,
                failed_rules=failed_rules,
                minimal_fix_instructions=instructions,
            )

        self._history.append(task)
        return task


class AgentScorecardTracker:
    """
    Tracks empirical engineering quality of each AI Agent (Section 8):
    - Defects per change
    - First-time fix effectiveness (%)
    - Regressions count
    - Post-deployment vulnerabilities
    """

    def __init__(self):
        self._agents: Dict[str, AgentQualityScorecard] = {}

    def record_change_evaluation(
        self,
        agent_id: str,
        defects_found: int,
        was_fix_attempt: bool = False,
        fix_succeeded_first_time: bool = False,
        regression_detected: bool = False,
        post_deploy_vuln: bool = False,
        tamper_blocked: bool = False,
    ) -> AgentQualityScorecard:
        card = self._agents.get(agent_id) or AgentQualityScorecard(agent_id=agent_id)
        card.total_changes += 1
        card.total_defects += max(0, defects_found)
        card.defects_per_change = round(card.total_defects / max(1, card.total_changes), 3)

        if was_fix_attempt:
            card.total_fix_attempts += 1
            if fix_succeeded_first_time:
                card.first_time_fix_count += 1
            card.first_time_fix_rate_pct = round(
                (card.first_time_fix_count / max(1, card.total_fix_attempts)) * 100.0, 2
            )

        if regression_detected:
            card.regressions_introduced += 1
        if post_deploy_vuln:
            card.post_deploy_vulnerabilities += 1
        if tamper_blocked:
            card.tamper_attempts_blocked += 1

        # Classify agent reliability tier
        if card.tamper_attempts_blocked > 0 or card.post_deploy_vulnerabilities > 0:
            card.reliability_tier = "RESTRICTED"
        elif card.defects_per_change <= 0.25 and card.first_time_fix_rate_pct >= 85.0:
            card.reliability_tier = "SOTA"
        elif card.defects_per_change <= 0.75:
            card.reliability_tier = "STANDARD"
        else:
            card.reliability_tier = "PROBATION"

        self._agents[agent_id] = card
        return card

    def get_all_scorecards(self) -> List[Dict[str, Any]]:
        return [c.model_dump() for c in self._agents.values()]


class AuditTrailRecorder:
    """
    Implements RAE-SEC-210 (Audit Trail Integrity):
    Maintains an append-only, SHA-256 hash-chained ledger of all quality gate verdicts and evidence.
    """

    def __init__(self):
        self._chain: List[Dict[str, Any]] = []

    def append_decision(
        self,
        operation: str,
        verdict: str,
        actor: str,
        evidence_summary: Dict[str, Any],
    ) -> Dict[str, Any]:
        prev_hash = self._chain[-1]["entry_sha256"] if self._chain else "0" * 64
        timestamp = datetime.now(timezone.utc).isoformat()
        payload = {
            "index": len(self._chain) + 1,
            "timestamp": timestamp,
            "operation": operation,
            "verdict": verdict,
            "actor": actor,
            "evidence_summary": evidence_summary,
            "prev_sha256": prev_hash,
        }
        canonical_json = json.dumps(payload, sort_keys=True, default=str)
        entry_hash = hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()
        entry = {**payload, "entry_sha256": entry_hash}
        self._chain.append(entry)
        return entry

    def verify_chain_integrity(self) -> Dict[str, Any]:
        prev = "0" * 64
        for idx, entry in enumerate(self._chain):
            if entry["prev_sha256"] != prev:
                return {"valid": False, "broken_at_index": idx + 1}
            check_payload = {k: v for k, v in entry.items() if k != "entry_sha256"}
            expected_hash = hashlib.sha256(
                json.dumps(check_payload, sort_keys=True, default=str).encode("utf-8")
            ).hexdigest()
            if expected_hash != entry["entry_sha256"]:
                return {"valid": False, "broken_at_index": idx + 1}
            prev = entry["entry_sha256"]
        return {"valid": True, "entries_count": len(self._chain), "head_sha256": prev}
