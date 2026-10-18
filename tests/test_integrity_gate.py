import pytest
from src.test_integrity_guard import TestIntegrityGuard
from main import QualitySentinel

def test_test_integrity_guard_pass():
    """Verifies that TestIntegrityGuard allows changes that preserve or improve test assertions."""
    guard = TestIntegrityGuard()

    baseline = """
def test_calc():
    assert 2 + 2 == 4
    assert 3 * 3 == 9
"""
    proposed = """
def test_calc():
    assert 2 + 2 == 4
    assert 3 * 3 == 9
    assert 5 - 1 == 4  # Additional assert
"""
    passed, reason = guard.validate_test_integrity(baseline, proposed)
    assert passed is True
    assert reason is None

def test_test_integrity_guard_drop_fail():
    """Verifies that TestIntegrityGuard rejects changes that drop assertions."""
    guard = TestIntegrityGuard()

    baseline = """
def test_calc():
    assert 2 + 2 == 4
    assert 3 * 3 == 9
"""
    proposed = """
def test_calc():
    assert 2 + 2 == 4  # Dropped one assert
"""
    passed, reason = guard.validate_test_integrity(baseline, proposed)
    assert passed is False
    assert "Assertion count dropped" in reason

def test_test_integrity_guard_softening_fail():
    """Verifies that TestIntegrityGuard rejects assertion softening (e.g. assert True replacement)."""
    guard = TestIntegrityGuard()

    baseline = """
def test_calc():
    assert 2 + 2 == 4
"""
    proposed = """
def test_calc():
    assert True  # Weakened assert
"""
    passed, reason = guard.validate_test_integrity(baseline, proposed)
    assert passed is False
    assert "Assertion softening detected" in reason or "Assertion count dropped" in reason

def test_quality_gate_baseline_coverage_rejection(monkeypatch):
    """Verifies that perform_static_audit rejects commits that drop coverage or introduce vulnerabilities."""
    import asyncio
    sentinel = QualitySentinel()
    
    # Mock SAST and Coverage Engine returns to simulate metrics
    class DummyReport:
        def __init__(self, score, critical_count=0):
            self.score = score
            self.critical_count = critical_count
            self.critical_count = critical_count
            self.critical_count = critical_count
            self.critical_count = critical_count
            
    # Mock run method
    async def mock_sast_run(self):
        # 1 critical vulnerability
        class SastRep:
            score = 70.0
            critical_count = 1
        return SastRep()
        
    async def mock_cov_run(self):
        # 75% coverage (baseline is 80.0%)
        class CovRep:
            score = 75.0
        return CovRep()

    from engines.security.sast import SastSecurityEngine
    from engines.testing.coverage import CoverageEngine
    
    monkeypatch.setattr(SastSecurityEngine, "run", mock_sast_run)
    monkeypatch.setattr(CoverageEngine, "run", mock_cov_run)

    result = asyncio.run(sentinel.perform_static_audit("/dummy/path"))
    assert "REJECTED" in result
    assert "dropped below baseline" in result
    assert "exceeds baseline" in result

