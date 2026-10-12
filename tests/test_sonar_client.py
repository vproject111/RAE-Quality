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

def test_sonar_client_aggregate_score():
    client = SonarQubeClient(base_url="http://mock-sonar:9000", token="mock-token")
    
    def side_effect(project_key):
        if project_key == "failed_proj":
            return {"project": project_key, "status": "ERROR", "is_ok": False}
        return {"project": project_key, "status": "OK", "is_ok": True}
        
    with patch.object(client, "get_project_quality_gate", side_effect=side_effect):
        res = client.get_aggregate_security_score(["proj1", "proj2", "failed_proj", "proj4"])
        assert res["all_gates_passed"] is False
        assert res["passed_count"] == 3
        assert res["total_count"] == 4
        assert res["verification_score"] == 0.75
        assert res["failed_projects"] == ["failed_proj"]
