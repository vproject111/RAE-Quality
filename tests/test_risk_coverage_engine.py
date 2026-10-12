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
