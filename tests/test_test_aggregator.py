# packages/rae-quality/tests/test_test_aggregator.py
import pytest
from unittest.mock import patch, MagicMock
from engines.testing.test_aggregator import UnifiedTestAggregator

def test_unified_test_aggregator_full_inventory():
    agg = UnifiedTestAggregator()
    res = agg.run_full_inventory()
    
    assert res["all_targets_met"] is True
    assert res["verification_score"] == 1.0
    assert res["total_combined_tests"] >= 2000
    
    # RAE-Suite verification
    rae = res["rae_suite"]
    assert rae["target_required"] == 1000
    assert rae["target_met"] is True
    assert rae["total_tests"] >= 1000
    assert rae["total_files"] > 0
    
    # Dreamsoft Factory verification
    ds = res["dreamsoft_factory"]
    assert ds["target_required"] == 1000
    assert ds["target_met"] is True
    assert ds["total_tests"] >= 1000
    assert ds["total_files"] > 0
    assert "editornext" in ds["modules"]
    assert "backend" in ds["modules"]

def test_unified_test_aggregator_target_not_met():
    agg = UnifiedTestAggregator()
    
    with patch.object(agg, "scan_rae_suite", return_value={"total_files": 10, "total_tests": 450, "target_required": 1000, "target_met": False}):
        with patch.object(agg, "scan_dreamsoft_factory", return_value={"total_files": 20, "total_tests": 1200, "target_required": 1000, "target_met": True}):
            res = agg.run_full_inventory()
            assert res["all_targets_met"] is False
            assert res["verification_score"] < 1.0
            assert res["total_combined_tests"] == 1650
