# packages/rae-quality/tests/test_mutation_runner.py
import pytest
from unittest.mock import patch
from engines.testing.mutation_runner import MutationCoverageEngine

def test_mutation_coverage_engine_full_audit():
    engine = MutationCoverageEngine()
    res = engine.run_full_mutation_audit()
    
    assert "all_mutations_passed" in res
    assert res["target_msi"] == 90.0
    assert res["overall_msi"] >= 85.0
    assert "modules" in res
    assert "stryker_editornext" in res["modules"]
    assert "infection_php_backend" in res["modules"]
    assert "mutmut_rae_suite" in res["modules"]

def test_mutation_coverage_engine_failure_detection():
    engine = MutationCoverageEngine()
    
    with patch.object(engine, "inspect_stryker_config", return_value={"configured": True, "msi": 72.0, "is_passing": False}):
        with patch.object(engine, "inspect_infection_php", return_value={"configured": True, "msi": 80.0, "is_passing": False}):
            with patch.object(engine, "inspect_mutmut_python", return_value={"configured": True, "msi": 70.0, "is_passing": False}):
                res = engine.run_full_mutation_audit()
                assert res["all_mutations_passed"] is False
                assert res["overall_msi"] < 90.0
                assert len(res["violations"]) >= 3
