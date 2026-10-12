# packages/rae-quality/tests/test_quality_api.py
import pytest
from fastapi.testclient import TestClient
from main import app

@pytest.fixture
def client():
    return TestClient(app)

def test_health_endpoint(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "healthy"}

def test_risk_coverage_endpoints(client):
    # Verify risk coverage calculation
    resp = client.get("/v2/quality/risk-coverage")
    assert resp.status_code == 200
    data = resp.json()
    assert "total_risk_coverage" in data
    assert "paths" in data
    assert len(data["paths"]) == 8

    # Verify live verification trigger
    verify_resp = client.post("/v2/quality/risk-coverage/verify")
    assert verify_resp.status_code == 200
    verify_data = verify_resp.json()
    assert "coverage" in verify_data
    assert verify_data["coverage"]["total_risk_coverage"] >= 95.0

def test_gate_decision_endpoint(client):
    resp = client.get("/v2/quality/gate-decision")
    assert resp.status_code == 200
    data = resp.json()
    assert "verdict" in data
    assert "can_deploy" in data
    assert data["verdict"] in ["LEVEL_1_APPROVED", "LEVEL_2_WARNING", "LEVEL_3_BLOCKED"]

def test_dtp_audit_endpoint(client):
    doc_spec = {
        "document_id": "test-card",
        "trimbox": {"width": 85.0, "height": 55.0},
        "bleedbox": {"width": 89.0, "height": 59.0},
        "dpi_min": 300.0,
        "text_elements": [
            {
                "font_name": "Inter",
                "font_size_pt": 9.0,
                "is_embedded": True,
                "color": {"c": 0, "m": 0, "y": 0, "k": 100}
            }
        ],
        "spot_layers": [
            {"name": "CutContour", "overprint": True}
        ]
    }
    resp = client.post("/v2/quality/dtp-audit", json=doc_spec)
    assert resp.status_code == 200
    res_data = resp.json()
    assert res_data["is_production_ready"] is True
    assert res_data["score"] == 1.0

def test_calculator_audit_endpoint(client):
    resp = client.post("/v2/quality/calculator-audit")
    assert resp.status_code == 200
    data = resp.json()
    assert data["passed"] is True
    assert data["verification_score"] == 1.0

def test_defect_metrics_endpoint(client):
    resp = client.get("/v2/quality/defect-metrics")
    assert resp.status_code == 200
    data = resp.json()
    assert "defect_escape_rate" in data
    assert "mttr_hours" in data

def test_golden_set_endpoint(client):
    resp = client.get("/v2/quality/golden-set-audit")
    assert resp.status_code == 200
    data = resp.json()
    assert data["total_documents"] == 5
    assert data["all_passed"] is True
    assert data["verification_score"] == 1.0

def test_sonarqube_endpoint(client):
    resp = client.get("/v2/quality/sonarqube-audit")
    assert resp.status_code == 200
    data = resp.json()
    assert "verification_score" in data
    assert "all_gates_passed" in data
    assert "total_count" in data

def test_predictive_plan_endpoint(client):
    payload = {"modified_files": ["editor/canvas.tsx", "pricing/matrix.py", "dtp/pdf_exporter.py"]}
    resp = client.post("/v2/quality/predictive-plan", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["modified_files"]) == 3
    assert "RC-01" in data["impacted_path_ids"]
    assert "RC-02" in data["impacted_path_ids"]

