# packages/rae-quality/tests/test_perfection_upgrade_v2.py
"""
Comprehensive verification of the RAE-Quality 2.0 Perfection Upgrade (G1-G5):
- G1: AIReviewEngine (6th core engine: semantic ownership, printshop admin isolation/audit, order logic)
- G2: Active detection for all 9 RAE-EDITOR-SECURITY rules (RAE-EDT-001 .. RAE-EDT-009)
- G3: OWASP & Identity detectors (CSRF, CORS, CSP, Weak Password Hash, JWT alg:none, Timing Attack, Webhook HMAC)
- G4: Baseline Fingerprint debt separation & 4-stage Rollout Phases (etap_1_p0 .. etap_4_prod)
- G5: AST-based TestIntegrityGuard wired into CodeQualityEngine.verify_fix()
"""

from engines.governance.ai_review_engine import AIReviewEngine
from engines.governance.quality_gateway_v2 import RAEQualityGatewayV2
from engines.security.security_gateway import SecurityGateway
from engines.testing.code_quality_engine import CodeQualityEngine


def test_g1_ai_review_engine_semantic_checks():
    engine = AIReviewEngine()

    # 1. Printshop admin bypass without tenant_id or audit_log -> RAE-EDT-003 BLOCK
    bad_admin_code = """
def get_all_orders(user):
    if user.role == "printshop_admin":
        return db.query(Order).all()
"""
    res1 = engine.review_change_semantics(bad_admin_code, file_path="orders_admin.py")
    assert res1["verdict"] == "BLOCK"
    assert any(f["rule_id"] == "RAE-EDT-003" for f in res1["findings"])

    # 2. Direct client manipulation of order status/discount -> RAE-SEC-202 BLOCK
    bad_order_logic = """
def update_order(req, order):
    order.status = req.body.status
    discount_percent = req.body.discount
"""
    res2 = engine.review_change_semantics(bad_order_logic, file_path="checkout.py")
    assert res2["verdict"] == "BLOCK"
    assert any(f["rule_id"] == "RAE-SEC-202" for f in res2["findings"])

    # 3. Clean endpoint with proper tenant_id, owner_id & audit_log -> PASS + EvidenceItems
    clean_code = """
@router.get("/projects/{project_id}")
def get_project(project_id: str, current_user = Depends(get_current_tenant)):
    check_project_owner(project_id, current_user.tenant_id, current_user.owner_id)
    audit_log.record("project_read", project_id=project_id, tenant_id=current_user.tenant_id)
    return db.query(Project).filter_by(id=project_id, tenant_id=current_user.tenant_id).first()
"""
    res3 = engine.review_change_semantics(clean_code, file_path="projects.py")
    assert res3["verdict"] == "PASS"
    assert res3["requirement_aligned"] is True
    assert len(res3["evidence_items"]) == 4
    assert res3["approved_review_id"].startswith("RAE-AI-REV-")


def test_g2_all_9_rae_editor_security_rules_active():
    gw = SecurityGateway()

    samples = {
        "RAE-EDT-001": "project = Project.get_by_id_unscoped(project_id)",
        "RAE-EDT-002": 'redis.set(f"project:{project_id}", payload)',
        "RAE-EDT-003": "allow_cross_printshop_admin = True",
        "RAE-EDT-004": "autosave_overwrite_without_version = True",
        "RAE-EDT-005": "order.total_price = req.body.price",
        "RAE-EDT-006": "preserve_exif_gps = True",
        "RAE-EDT-007": "share_token = md5(project_id)",
        "RAE-EDT-008": "render_worker_privileged = True",
        "RAE-EDT-009": "skip_storage_cleanup_on_gdpr_delete = True",
    }

    for expected_rule_id, snippet in samples.items():
        scan = gw.scan_code(snippet, file_path="editor_service.py")
        found_ids = {f["rule_id"] for f in scan["findings"]}
        assert expected_rule_id in found_ids, f"Missing detector for {expected_rule_id}"


def test_g3_owasp_and_identity_extended_detectors():
    gw = SecurityGateway()

    samples = {
        "RAE-SEC-003": "verify_csrf = False",
        "RAE-SEC-004": 'allow_origins = ["*"], allow_credentials = True',
        "RAE-SEC-010": "Content-Security-Policy: default-src 'self' 'unsafe-eval'",
        "RAE-SEC-023": "digest = hashlib.md5(password).hexdigest()",
        "RAE-SEC-024": 'jwt.decode(token, key, algorithms=["none"])',
        "RAE-SEC-032": "if webhook_signature == expected_signature: pass",
        "RAE-SEC-034": "verify_webhook_signature = False",
    }

    for expected_rule_id, snippet in samples.items():
        scan = gw.scan_code(snippet, file_path="auth_security.py")
        found_ids = {f["rule_id"] for f in scan["findings"]}
        assert expected_rule_id in found_ids, f"Missing detector for {expected_rule_id}"


def test_g4_baseline_fingerprint_separation_and_rollout_phases():
    gateway = RAEQualityGatewayV2()
    legacy_line = "digest = hashlib.md5(password).hexdigest()"

    # First scan without baseline -> BLOCK
    initial = gateway.security_scan({"code": legacy_line, "file_path": "legacy_auth.py"})
    assert initial["verdict"] == "BLOCK"
    assert initial["findings_count"] == 1
    fp = initial["findings"][0]["evidence"]["fingerprint"]
    assert fp

    # Second scan with fingerprint in baseline -> PASS (historical debt tracked separately, not blocking unrelated change)
    with_baseline = gateway.security_scan({
        "code": legacy_line,
        "file_path": "legacy_auth.py",
        "baseline_fingerprints": [fp],
    })
    assert with_baseline["verdict"] == "PASS"
    assert with_baseline["findings_count"] == 0
    assert with_baseline["baseline_debt_count"] == 1

    # Rollout phase filtering (Section 10: etap_1_p0 vs etap_4_prod)
    p0_policy = gateway.get_policy({
        "task_description": "Update order database migration and k8s deployment",
        "modified_files": ["migrations/002_orders.py", "k8s/deployment.yaml"],
        "rollout_phase": "etap_1_p0",
    })
    prod_policy = gateway.get_policy({
        "task_description": "Update order database migration and k8s deployment",
        "modified_files": ["migrations/002_orders.py", "k8s/deployment.yaml"],
        "rollout_phase": "etap_4_prod",
    })
    assert p0_policy["rollout_phase"] == "etap_1_p0"
    assert all(r["priority"] == "P0" for r in p0_policy["rules"])
    assert prod_policy["selected_rules_count"] >= p0_policy["selected_rules_count"]


def test_g5_ast_test_integrity_guard_in_verify_fix():
    cqe = CodeQualityEngine()
    canonical_test = """
def test_tenant_isolation():
    assert response.status_code == 403
    assert response.json()["error"] == "forbidden"
"""
    softened_test = """
def test_tenant_isolation():
    assert response.status_code == 403
    assert True
"""
    res = cqe.verify_fix(
        original_code="tenant_id = req.body.tenantId",
        fixed_code="tenant_id = session.authenticated_tenant_id",
        rule_id="RAE-SEC-006",
        canonical_test_code=canonical_test,
        agent_submitted_test_code=softened_test,
    )
    assert res["verdict"] == "BLOCK"
    assert res["tamper_detected"] is True
    assert "Assertion softening detected" in res["reason"]
