# packages/rae-quality/tests/test_iteration2_agent_control_and_repair.py
import pytest
from engines.testing.code_quality_engine import CodeQualityEngine
from engines.governance.auto_repair import (
    AutoRepairOrchestrator,
    AgentScorecardTracker,
    AuditTrailRecorder,
)
from models.security_v2 import GatewayVerdict


def test_generate_negative_and_tenant_isolation_tests():
    engine = CodeQualityEngine()
    res = engine.generate_tests(
        target_endpoint="/api/v1/projects/{id}",
        component="editor_api",
        rule_ids=["RAE-SEC-006", "RAE-SEC-008", "RAE-SEC-090"],
    )
    assert res["total_generated"] == 3
    assert "test_neg_idor_001" in res["pytest_template"]
    assert "test_neg_mass_003" in res["pytest_template"]
    assert "test_neg_race_008" in res["pytest_template"]


def test_verify_fix_blocks_agent_test_tampering_and_verifies_real_fix():
    engine = CodeQualityEngine()
    vuln_code = 'def get_proj(req):\n    tid = req.body.tenantId\n    return tid\n'
    clean_code = 'def get_proj(session: dict) -> str:\n    return str(session.get("tenant_id", ""))\n'
    canonical_test = "def test_idor():\n    assert response.status_code == 403\n"
    tampered_test = "def test_idor():\n    assert response.status_code == 200\n"

    # 1. Agent tampers with the security test to make it pass -> BLOCK
    tamper_res = engine.verify_fix(
        original_code=vuln_code,
        fixed_code=vuln_code,
        rule_id="RAE-SEC-006",
        canonical_test_code=canonical_test,
        agent_submitted_test_code=tampered_test,
    )
    assert tamper_res["verdict"] == GatewayVerdict.BLOCK.value
    assert tamper_res["tamper_detected"] is True

    # 2. Agent submits genuine fix without modifying canonical test -> PASS
    ok_res = engine.verify_fix(
        original_code=vuln_code,
        fixed_code=clean_code,
        rule_id="RAE-SEC-006",
        canonical_test_code=canonical_test,
        agent_submitted_test_code=canonical_test,
    )
    assert ok_res["verdict"] == GatewayVerdict.PASS.value
    assert ok_res["fix_verified"] is True


def test_auto_repair_max_3_attempts_then_human_escalation():
    orchestrator = AutoRepairOrchestrator()
    findings = [{"rule_id": "RAE-SEC-006", "remediation": "Resolve tenant_id from server session"}]

    # Attempt 1 -> REPAIR
    t1 = orchestrator.evaluate_or_schedule_repair("PR-101", "agent-codex", findings)
    assert t1.attempt == 1
    assert t1.verdict == GatewayVerdict.REPAIR
    assert t1.escalated_to_human is False

    # Attempt 2 -> REPAIR
    t2 = orchestrator.evaluate_or_schedule_repair("PR-101", "agent-codex", findings)
    assert t2.attempt == 2
    assert t2.verdict == GatewayVerdict.REPAIR

    # Attempt 3 -> REPAIR
    t3 = orchestrator.evaluate_or_schedule_repair("PR-101", "agent-codex", findings)
    assert t3.attempt == 3
    assert t3.verdict == GatewayVerdict.REPAIR
    assert t3.escalated_to_human is False

    # Attempt 4 (exceeds MAX_ATTEMPTS = 3) -> BLOCK & Escalate to Human Review
    t4 = orchestrator.evaluate_or_schedule_repair("PR-101", "agent-codex", findings)
    assert t4.attempt == 4
    assert t4.verdict == GatewayVerdict.BLOCK
    assert t4.escalated_to_human is True


def test_agent_scorecard_and_immutable_audit_trail():
    tracker = AgentScorecardTracker()
    card = tracker.record_change_evaluation(
        agent_id="antigravity",
        defects_found=0,
        was_fix_attempt=True,
        fix_succeeded_first_time=True,
    )
    assert card.reliability_tier == "SOTA"
    assert card.first_time_fix_rate_pct == 100.0

    bad_card = tracker.record_change_evaluation(
        agent_id="rogue-agent",
        defects_found=3,
        tamper_blocked=True,
    )
    assert bad_card.reliability_tier == "RESTRICTED"

    recorder = AuditTrailRecorder()
    recorder.append_decision("quality.release_gate", "BLOCK", "RAE-Quality", {"rule": "RAE-SEC-006"})
    recorder.append_decision("quality.verify_fix", "PASS", "RAE-Quality", {"rule": "RAE-SEC-006"})
    integrity = recorder.verify_chain_integrity()
    assert integrity["valid"] is True
    assert integrity["entries_count"] == 2
