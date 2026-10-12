# packages/rae-quality/tests/test_calculator_verifier.py
import pytest
from engines.testing.calculator_verifier import CalculatorVerifier

def test_price_monotonicity_valid():
    verifier = CalculatorVerifier()
    valid_tiers = [
        {"volume": 100, "total_price": 50.0},
        {"volume": 250, "total_price": 90.0},
        {"volume": 500, "total_price": 140.0},
        {"volume": 1000, "total_price": 220.0},
    ]
    res = verifier.verify_price_monotonicity(valid_tiers)
    assert res["is_valid"] is True
    assert len(res["violations"]) == 0

def test_price_monotonicity_inversion_detected():
    verifier = CalculatorVerifier()
    # 500 units cheaper than 250 units -> critical error
    broken_tiers = [
        {"volume": 100, "total_price": 50.0},
        {"volume": 250, "total_price": 120.0},
        {"volume": 500, "total_price": 100.0},
    ]
    res = verifier.verify_price_monotonicity(broken_tiers)
    assert res["is_valid"] is False
    assert any("Total price inversion" in v for v in res["violations"])

def test_unit_price_inversion_detected():
    verifier = CalculatorVerifier()
    # 1000 units has higher unit price than 500 units
    broken_tiers = [
        {"volume": 500, "total_price": 100.0},   # unit: 0.20
        {"volume": 1000, "total_price": 300.0},  # unit: 0.30 -> broken!
    ]
    res = verifier.verify_price_monotonicity(broken_tiers)
    assert res["is_valid"] is False
    assert any("Unit price inversion" in v for v in res["violations"])

def test_format_proportionality():
    verifier = CalculatorVerifier()
    # A5 vs A4
    res = verifier.verify_format_proportionality(
        base_format_price=100.0,
        larger_format_price=180.0,
        format_ratio=2.0
    )
    assert res["is_valid"] is True

    # Broken: larger format cheaper than base
    res_broken = verifier.verify_format_proportionality(
        base_format_price=100.0,
        larger_format_price=80.0,
        format_ratio=2.0
    )
    assert res_broken["is_valid"] is False

def test_full_suite_execution():
    verifier = CalculatorVerifier()
    suite_res = verifier.run_full_suite()
    assert "passed" in suite_res
    assert suite_res["passed"] is True
    assert suite_res["verification_score"] == 1.0
    assert suite_res["latency"]["passed_threshold"] is True
