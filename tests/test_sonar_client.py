# packages/rae-quality/tests/test_sonar_client.py
import pytest
from unittest.mock import patch, MagicMock
from engines.security.sonar_client import SonarQubeClient

def test_sonar_client_system_status():
    client = SonarQubeClient(base_url="http://mock-sonar:9000", token="mock-token")
    with patch("httpx.Client.get") as mock_get:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"status": "UP", "version": "26.6.0"}
        mock_get.return_value = mock_resp
        
        status = client.get_system_status()
        assert status["status"] == "UP"
        assert status["version"] == "26.6.0"

def test_sonar_client_project_quality_gate_ok():
    client = SonarQubeClient(base_url="http://mock-sonar:9000", token="mock-token")
    with patch("httpx.Client.get") as mock_get:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "projectStatus": {
                "status": "OK",
                "conditions": [{"metricKey": "coverage", "status": "OK"}]
            }
        }
        mock_get.return_value = mock_resp
        
        qg = client.get_project_quality_gate("editornext")
        assert qg["project"] == "editornext"
        assert qg["status"] == "OK"
        assert qg["is_ok"] is True

def test_sonar_client_project_quality_gate_error():
    client = SonarQubeClient(base_url="http://mock-sonar:9000", token="mock-token")
    with patch("httpx.Client.get", side_effect=Exception("Connection refused")):
        qg = client.get_project_quality_gate("editornext")
        assert qg["project"] == "editornext"
        assert qg["status"] == "ERROR"
        assert qg["is_ok"] is False

def test_sonar_client_strict_measures_ok():
    client = SonarQubeClient(base_url="http://mock-sonar:9000", token="mock-token")
    with patch("httpx.Client.get") as mock_get:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "component": {
                "measures": [
                    {"metric": "vulnerabilities", "value": "0"},
                    {"metric": "bugs", "value": "0"},
                    {"metric": "code_smells", "value": "0"},
                    {"metric": "security_hotspots", "value": "0"},
                    {"metric": "coverage", "value": "95.5"},
                    {"metric": "duplicated_lines_density", "value": "0.0"}
                ]
            }
        }
        mock_get.return_value = mock_resp
        
        strict = client.get_strict_project_measures("editornext")
        assert strict["is_strict_a"] is True
        assert len(strict["violations"]) == 0
        assert strict["coverage"] == 95.5
        assert strict["bugs"] == 0

def test_sonar_client_strict_measures_violation():
    client = SonarQubeClient(base_url="http://mock-sonar:9000", token="mock-token")
    with patch("httpx.Client.get") as mock_get:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "component": {
                "measures": [
                    {"metric": "vulnerabilities", "value": "1"},  # P0 violation
                    {"metric": "bugs", "value": "2"},             # P0 violation
                    {"metric": "code_smells", "value": "5"},
                    {"metric": "security_hotspots", "value": "0"},
                    {"metric": "coverage", "value": "84.2"},      # Below 90%
                    {"metric": "duplicated_lines_density", "value": "1.5"}
                ]
            }
        }
        mock_get.return_value = mock_resp
        
        strict = client.get_strict_project_measures("editornext")
        assert strict["is_strict_a"] is False
        assert len(strict["violations"]) >= 4
        assert any("Vulnerabilities" in v for v in strict["violations"])
        assert any("Bugs" in v for v in strict["violations"])
        assert any("Coverage" in v for v in strict["violations"])

def test_sonar_client_aggregate_score():
    client = SonarQubeClient(base_url="http://mock-sonar:9000", token="mock-token")
    
    def side_effect_qg(project_key):
        if project_key == "failed_proj":
            return {"project": project_key, "status": "ERROR", "is_ok": False}
        return {"project": project_key, "status": "OK", "is_ok": True}

    def side_effect_strict(project_key):
        if project_key == "failed_proj":
            return {"project": project_key, "is_strict_a": False, "violations": ["Bugs: 1"]}
        return {"project": project_key, "is_strict_a": True, "violations": []}
        
    with patch.object(client, "get_project_quality_gate", side_effect=side_effect_qg):
        with patch.object(client, "get_strict_project_measures", side_effect=side_effect_strict):
            res = client.get_aggregate_security_score(["proj1", "proj2", "failed_proj", "proj4"])
            assert res["all_gates_passed"] is False
            assert res["all_strict_a_passed"] is False
            assert res["passed_count"] == 3
            assert res["total_count"] == 4
            assert res["verification_score"] == 0.75
            assert res["failed_projects"] == ["failed_proj"]
            assert len(res["strict_measures"]) == 4
