# packages/rae-quality/tests/test_risk_coverage_engine.py
import pytest
from engines.governance.risk_coverage_engine import RiskCoverageEngine
from models.risk import DeploymentGateVerdict, PathStatus, RiskSeverity

def test_risk_coverage_calculation_initial():
    engine = RiskCoverageEngine()
    coverage = engine.calculate_risk_coverage()
    assert coverage.total_risk_coverage == 0.0
    assert coverage.total_weight > 0
    assert len(coverage.paths) == 8

def test_risk_coverage_after_live_verification():
    engine = RiskCoverageEngine()
    engine.run_automated_live_verification()
    coverage = engine.calculate_risk_coverage()
    
    # After live verification, all 8 paths are verified
    assert coverage.total_risk_coverage >= 95.0
    assert coverage.p0_violations == 0
    
    gate = engine.evaluate_deployment_gate()
    assert gate.verdict == DeploymentGateVerdict.LEVEL_1_APPROVED
    assert gate.can_deploy is True
    assert len(gate.blockers) == 0

def test_p0_violation_triggers_level_3_blocked():
    engine = RiskCoverageEngine()
    engine.run_automated_live_verification()
    
    # Simulate a critical P0 failure in Pricing Calculation (RC-01)
    engine.update_path_score("RC-01", verification_score=0.40, details={"error": "Negative margin on large order"})
    
    coverage = engine.calculate_risk_coverage()
    assert coverage.p0_violations >= 1
    
    gate = engine.evaluate_deployment_gate()
    assert gate.verdict == DeploymentGateVerdict.LEVEL_3_BLOCKED
    assert gate.can_deploy is False
    assert any("CRITICAL P0 BLOCKER" in b for b in gate.blockers)

def test_warning_level_2_gate():
    engine = RiskCoverageEngine()
    engine.run_automated_live_verification()
    
    # Simulate P1 degradation without P0 failure
    engine.update_path_score("RC-05", verification_score=0.70)
    engine.update_path_score("RC-06", verification_score=0.75)
    
    coverage = engine.calculate_risk_coverage()
    assert coverage.p0_violations == 0
    
    gate = engine.evaluate_deployment_gate()
    if coverage.total_risk_coverage < 95.0:
        assert gate.verdict == DeploymentGateVerdict.LEVEL_2_WARNING
        assert gate.can_deploy is False

def test_predictive_test_plan():
    engine = RiskCoverageEngine()
    # Test modified files mapping
    files = [
        "packages/editor/render.ts",
        "apps/calc/pricing.py",
        "packages/rae-core/auth/jwt.py"
    ]
    plan = engine.get_predictive_test_plan(files)
    assert len(plan["modified_files"]) == 3
    assert "RC-01" in plan["impacted_path_ids"]
    assert "RC-02" in plan["impacted_path_ids"]
    assert "RC-07" in plan["impacted_path_ids"]
    assert len(plan["recommended_tests"]) >= 3
    assert plan["has_p0_impacted"] is True

def test_defect_tracker_and_cfr():
    from engines.governance.defect_tracker import DefectTracker
    from models.risk import RiskSeverity
    from datetime import datetime, timedelta, timezone
    
    tracker = DefectTracker()
    tracker.register_deployment(success=True)
    tracker.register_deployment(success=True)
    tracker.register_deployment(success=False)
    
    # 1 fail out of 3 = 33.33% CFR
    m = tracker.calculate_metrics()
    assert m.change_failure_rate == 33.33
    
    # Register defects
    now = datetime.now(timezone.utc)
    tracker.register_defect("CI Syntax Error", RiskSeverity.P3, detected_at="CI", system="editor")
    tracker.register_defect("Prod Crash", RiskSeverity.P0, detected_at="PRODUCTION", system="backend", resolved_at=now + timedelta(hours=2))
    
    metrics = tracker.calculate_metrics()
    assert metrics.total_defects == 2
    assert metrics.production_defects == 1
    assert metrics.ci_defects == 1
    assert metrics.defect_escape_rate == 50.0
    assert metrics.severity_weighted_score == 101 # 100 (P0) + 1 (P3)
    assert metrics.mttr_hours == 2.0

