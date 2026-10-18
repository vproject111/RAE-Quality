# packages/rae-quality/tests/test_iteration4_gateway_v2_and_infra.py
import pytest
from fastapi.testclient import TestClient
from main import app, handle_list_tools, handle_call_tool
from engines.infrastructure.infrastructure_engine import InfrastructureEngine


@pytest.fixture
def client():
    return TestClient(app)


def test_infrastructure_engine_dockerfile_k8s_and_systemic():
    infra = InfrastructureEngine()

    bad_dockerfile = "FROM ubuntu:22.04\nCOPY . /app\nCMD ['python', 'main.py']\n"
    df_findings = infra.audit_dockerfile(bad_dockerfile)
    df_rules = {f.rule_id for f in df_findings}
    assert "RAE-SEC-190" in df_rules  # Missing multi-stage build
    assert "RAE-SEC-191" in df_rules  # Missing non-root USER
    assert "RAE-SEC-141" in df_rules  # Missing HEALTHCHECK

    bad_k8s = "apiVersion: apps/v1\nkind: Deployment\nspec:\n  containers:\n    - name: api\n      image: app:1.0\n"
    k8s_findings = infra.audit_k8s_manifest(bad_k8s)
    k8s_rules = {f.rule_id for f in k8s_findings}
    assert "RAE-SEC-193" in k8s_rules  # Missing resources.requests/limits
    assert "RAE-SEC-142" in k8s_rules  # Missing liveness/readiness probes

    sys_fail = infra.evaluate_systemic_readiness({"backup_restore_tested": False, "tls_days_remaining": 5})
    assert sys_fail["verdict"] == "BLOCK"


def test_section8_pr_assessment_dual_gate_simulation(client):
    """
    Tests exact Section 8 Pull Request example from poziom-bezpieczeństwa-kodu.md:
    - Quality Score: 87/100
    - Tests passed: 246/250 (4 failed)
    - SQL Injection: PASS
    - Cross-tenant authorization: BLOCK
    - Secrets scanning: PASS
    - OpenAPI compatibility: PASS
    - Concurrency regression: REVIEW
    -> Decision: BLOCK (Merge zablokowany)
    """
    resp = client.post(
        "/v2/quality/release-gate",
        json={
            "code": "def get_order(req):\n    tid = req.body.tenantId\n    return tid\n",
            "tests_passed": 246,
            "tests_total": 250,
            "concurrency_review": True,
            "quality_score_override_for_simulation": 87,
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["verdict"] == "BLOCK"
    assert data["merge_allowed"] is False
    assert data["quality_score"] == 87
    assert data["tests_passed"] == 246
    assert data["tests_total"] == 250
    assert data["tests_failed"] == 4

    gates_by_name = {g["name"]: g["verdict"] for g in data["mandatory_gates"]}
    assert gates_by_name["SQL Injection"] == "PASS"
    assert gates_by_name["Cross-tenant authorization"] == "BLOCK"
    assert gates_by_name["Secrets scanning"] == "PASS"
    assert gates_by_name["OpenAPI compatibility"] == "PASS"
    assert gates_by_name["Concurrency regression"] == "REVIEW"


def test_all_8_rest_and_rpc_operations_and_9_acceptance_criteria(client):
    # 1. quality.get_policy
    r1 = client.post("/v2/quality/policy", json={"task_description": "Order checkout API", "modified_files": ["order.py"]})
    assert r1.status_code == 200
    assert r1.json()["total_catalog_rules"] == 219

    # 2. quality.analyze_diff
    r2 = client.post("/v2/quality/analyze-diff", json={"diff": "x = 1", "modified_files": ["clean.py"], "agent_id": "antigravity"})
    assert r2.status_code == 200
    assert r2.json()["verdict"] == "PASS"

    # 3. quality.security_scan
    r3 = client.post("/v2/quality/security-scan", json={"code": "def ok(a: int) -> int:\n    return a\n"})
    assert r3.status_code == 200
    assert r3.json()["verdict"] == "PASS"
    assert r3.json()["sarif"]["version"] == "2.1.0"

    # 4. quality.generate_tests
    r4 = client.post("/v2/quality/generate-tests", json={"target_endpoint": "/v1/orders"})
    assert r4.status_code == 200
    assert r4.json()["total_generated"] == 10

    # 5. quality.verify_fix
    r5 = client.post(
        "/v2/quality/verify-fix",
        json={
            "original_code": "tid = req.body.tenantId",
            "fixed_code": "def get_tid(s: dict) -> str:\n    return str(s.get('tenant_id', ''))\n",
            "rule_id": "RAE-SEC-006",
        },
    )
    assert r5.status_code == 200
    assert r5.json()["verdict"] == "PASS"

    # 6. quality.check_architecture
    r6 = client.post("/v2/quality/check-architecture", json={"code": "def ok() -> int:\n    return 1\n"})
    assert r6.status_code == 200
    assert r6.json()["verdict"] == "PASS"

    # 7. quality.release_gate (clean pass)
    r7 = client.post("/v2/quality/release-gate", json={"code": "def ok() -> int:\n    return 1\n", "tests_passed": 250, "tests_total": 250})
    assert r7.status_code == 200
    assert r7.json()["verdict"] == "PASS"
    assert r7.json()["merge_allowed"] is True

    # 8. quality.report & 9/9 Acceptance Criteria
    r8 = client.get("/v2/quality/report")
    assert r8.status_code == 200
    rep = r8.json()
    assert rep["acceptance_criteria_score"] == "9/9"
    assert rep["all_acceptance_criteria_met"] is True
    assert rep["audit_trail_integrity"]["valid"] is True

    # Unified RPC dispatcher
    r_rpc = client.post("/v2/quality/rpc", json={"operation": "quality.get_policy", "params": {"task_description": "test"}})
    assert r_rpc.status_code == 200
    assert r_rpc.json()["total_catalog_rules"] == 219


@pytest.mark.asyncio
async def test_mcp_tools_expose_all_8_operations():
    tools = await handle_list_tools()
    tool_names = {t.name for t in tools}
    for op in (
        "quality.get_policy",
        "quality.analyze_diff",
        "quality.security_scan",
        "quality.generate_tests",
        "quality.verify_fix",
        "quality.check_architecture",
        "quality.release_gate",
        "quality.report",
    ):
        assert op in tool_names

    mcp_res = await handle_call_tool("quality.report", {})
    assert len(mcp_res) == 1
    assert '"acceptance_criteria_score": "9/9"' in mcp_res[0].text
