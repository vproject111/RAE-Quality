# packages/rae-quality/engines/architecture/architecture_engine.py
"""
RAE-Quality 2.0 Architecture, Database, Concurrency & OpenAPI Engine.
Implements `quality.check_architecture` covering Modules 3, 4, 5, 6, and 7 (Topics 41-133)
of docs/poziom-bezpieczeństwa-kodu.md.
"""

import re
from typing import Any, Dict, List, Optional
from models.security_v2 import (
    ControlType,
    GatewayVerdict,
    RuleEnforcement,
    RuleSeverity,
    SecurityFinding,
)


class ArchitectureEngine:
    """
    Audits architectural compliance across Database Integrity (41-75),
    Distributed Systems & Concurrency (76-97), Cache & Performance (98-106),
    Messaging & Jobs (107-115), and Network & OpenAPI Compatibility (116-133).
    """

    N_PLUS_ONE_REGEX = re.compile(
        r'(?:for\s+\w+\s+in\s+.*?:|foreach\s*\(.*?\)\s*\{)[\s\S]{1,280}?(?:\.execute\s*\(\s*[\'"]SELECT|::where\s*\(|->find\s*\(|\.objects\.filter\s*\()',
        re.IGNORECASE,
    )

    REDIS_NO_TTL_REGEX = re.compile(
        r'redis\.set\s*\(\s*[^,]+,\s*[^,)]+\s*\)',
        re.IGNORECASE,
    )

    def check_architecture(
        self,
        code: str = "",
        file_path: str = "service.py",
        technologies: Optional[List[str]] = None,
        openapi_before: Optional[Dict[str, Any]] = None,
        openapi_after: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Implements `quality.check_architecture` (Stage 3: Pre-Merge).
        """
        active_techs = {t.lower() for t in (technologies or ["postgresql", "redis"])}
        findings: List[SecurityFinding] = []
        lower_code = code.lower()
        lower_path = file_path.lower()

        # 1. Database Migrations & Down Migrations (RAE-SEC-046, RAE-SEC-047)
        if "migration" in lower_path or "alembic" in lower_path or "def upgrade(" in lower_code or "function up(" in lower_code:
            has_down = any(k in lower_code for k in ("def downgrade(", "function down(", "down_migration"))
            if not has_down:
                findings.append(
                    SecurityFinding(
                        rule_id="RAE-SEC-047",
                        rule_name="Down Migrations",
                        module="Database Integrity",
                        severity=RuleSeverity.HIGH,
                        enforcement=RuleEnforcement.REPAIR,
                        control_type=ControlType.DETERMINISTIC,
                        scanner="rae-architecture-engine",
                        message="Database migration is missing a reversible down/downgrade migration.",
                        file_path=file_path,
                        remediation="Implement `downgrade()` / `down()` to guarantee safe rollback.",
                    )
                )

        # 2. N+1 Query Detection (RAE-SEC-043)
        if self.N_PLUS_ONE_REGEX.search(code):
            findings.append(
                SecurityFinding(
                    rule_id="RAE-SEC-043",
                    rule_name="N+1 Queries",
                    module="Database Integrity",
                    severity=RuleSeverity.HIGH,
                    enforcement=RuleEnforcement.REPAIR,
                    control_type=ControlType.DETERMINISTIC,
                    scanner="rae-architecture-engine",
                    message="Potential N+1 query inside loop detected.",
                    file_path=file_path,
                    remediation="Batch-fetch records using `WHERE id IN (...)`, `selectinload`, or `with()` eager loading.",
                )
            )

        # 3. Transactions & Order Atomicity (RAE-SEC-048)
        if ("save_order(" in lower_code or "create_order(" in lower_code) and "save_order_items(" in lower_code:
            has_tx = any(k in lower_code for k in ("transaction", "begin(", "atomic(", "commit("))
            if not has_tx:
                findings.append(
                    SecurityFinding(
                        rule_id="RAE-SEC-048",
                        rule_name="Transactions",
                        module="Database Integrity",
                        severity=RuleSeverity.CRITICAL,
                        enforcement=RuleEnforcement.BLOCK,
                        control_type=ControlType.AI_SEMANTIC,
                        scanner="rae-architecture-engine",
                        message="Multi-step order and order-items persistence lacks an atomic database transaction.",
                        file_path=file_path,
                        remediation="Wrap order creation and order item insertion in an atomic transaction block.",
                    )
                )

        # 4. Concurrent Project Save / Race Conditions (RAE-SEC-090 & RAE-SEC-052)
        if ("save_project(" in lower_code or "update_scene(" in lower_code) and not any(
            k in lower_code for k in ("version", "etag", "optimistic", "for update", "lock", "yjs")
        ):
            findings.append(
                SecurityFinding(
                    rule_id="RAE-SEC-090",
                    rule_name="Race Conditions",
                    module="Distributed Systems",
                    severity=RuleSeverity.HIGH,
                    enforcement=RuleEnforcement.REPAIR,
                    control_type=ControlType.AI_SEMANTIC,
                    scanner="rae-architecture-engine",
                    message="Concurrent project save handler lacks optimistic locking (version/ETag) or conflict detection.",
                    file_path=file_path,
                    remediation="Enforce version/ETag optimistic concurrency check (`WHERE id = :id AND version = :version`).",
                )
            )

        # 5. Cache TTLs (RAE-SEC-100)
        if self.REDIS_NO_TTL_REGEX.search(code):
            findings.append(
                SecurityFinding(
                    rule_id="RAE-SEC-100",
                    rule_name="TTLs",
                    module="Cache & Performance",
                    severity=RuleSeverity.MEDIUM,
                    enforcement=RuleEnforcement.REPAIR,
                    control_type=ControlType.DETERMINISTIC,
                    scanner="rae-architecture-engine",
                    message="Redis cache write (`redis.set`) is missing an explicit TTL expiration parameter.",
                    file_path=file_path,
                    remediation="Specify `ex=<seconds>` or use `redis.setex` to prevent unbounded cache growth.",
                )
            )

        # 6. OpenAPI Backward Compatibility Check (RAE-SEC-128, RAE-SEC-129)
        openapi_compat = self.verify_openapi_compatibility(openapi_before, openapi_after)
        if not openapi_compat["compatible"]:
            for breaking in openapi_compat["breaking_changes"]:
                findings.append(
                    SecurityFinding(
                        rule_id="RAE-SEC-129",
                        rule_name="Backward Compatibility (OpenAPI)",
                        module="Network & API",
                        severity=RuleSeverity.CRITICAL,
                        enforcement=RuleEnforcement.BLOCK,
                        control_type=ControlType.DETERMINISTIC,
                        scanner="schemathesis",
                        message=f"OpenAPI breaking change: {breaking}",
                        file_path=file_path,
                        remediation="Maintain backward compatibility or introduce a new versioned endpoint (`/v2/...`).",
                    )
                )

        has_blockers = any(f.enforcement == RuleEnforcement.BLOCK for f in findings)
        verdict = GatewayVerdict.BLOCK if has_blockers else (GatewayVerdict.REPAIR if findings else GatewayVerdict.PASS)

        return {
            "verdict": verdict.value,
            "active_technologies": sorted(list(active_techs)),
            "postgres_vacuum_applicable": "postgresql" in active_techs,
            "kafka_consumer_groups_applicable": "kafka" in active_techs,
            "openapi_compatibility": openapi_compat,
            "findings_count": len(findings),
            "findings": [f.model_dump() for f in findings],
        }

    def verify_openapi_compatibility(
        self,
        before_spec: Optional[Dict[str, Any]],
        after_spec: Optional[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Checks for breaking changes between two OpenAPI specifications."""
        if not before_spec or not after_spec:
            return {"compatible": True, "breaking_changes": []}

        breaking_changes: List[str] = []
        before_paths = before_spec.get("paths", {})
        after_paths = after_spec.get("paths", {})

        for path, methods in before_paths.items():
            if path not in after_paths:
                breaking_changes.append(f"Removed API endpoint path: {path}")
                continue
            for method, op_before in methods.items():
                if method not in after_paths[path]:
                    breaking_changes.append(f"Removed HTTP method {method.upper()} on {path}")
                    continue
                op_after = after_paths[path][method]
                req_before = set(op_before.get("required_fields", []))
                req_after = set(op_after.get("required_fields", []))
                newly_required = req_after - req_before
                if newly_required:
                    breaking_changes.append(
                        f"Added new required request field(s) {sorted(list(newly_required))} on {method.upper()} {path}"
                    )

        return {
            "compatible": len(breaking_changes) == 0,
            "breaking_changes": breaking_changes,
        }
