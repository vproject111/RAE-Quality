# packages/rae-quality/engines/policy/policy_engine.py
"""
RAE-Quality 2.0 Policy Engine.
Handles:
- Dynamic selection of rules based on modified files, technology stack, and risk profile (quality.get_policy)
- Strict evidence verification (rejecting bare agent statements like "sprawdziłem bezpieczeństwo")
- Agent Self-Modification Protection (blocking agents from disabling rules or overriding gates)
- Technical Implementation Manifest generation across all 219 rules
"""

from typing import Any, Dict, List, Optional
from engines.policy.catalog_198 import (
    ADDITIONAL_AI_SAAS_TOPICS,
    ALL_198_TOPICS,
    MODULE_DEFINITIONS,
    RAE_EDITOR_SECURITY_RULES,
    build_full_rule_catalog,
)
from models.security_v2 import (
    EvidenceItem,
    ModulePriority,
    QualityRule,
)


class PolicyEngine:
    """Central Policy & Rule Engine for RAE-Quality 2.0."""

    # Protected governance files that coding agents are forbidden from weakening
    PROTECTED_QUALITY_PATHS = (
        "packages/rae-quality/engines/policy",
        "packages/rae-quality/engines/security",
        "packages/rae-quality/engines/governance",
        "scripts/hard_contract_gatekeeper.py",
        "AGENT_CORE_PROTOCOL.md",
    )

    # Section 10: 4-Stage Rollout Plan (Plan wdrożenia etapami)
    ROLLOUT_PHASES: Dict[str, List[str]] = {
        "etap_1_p0": ["P0"],
        "etap_2_p1": ["P0", "P1"],
        "etap_3_p2": ["P0", "P1", "P2"],
        "etap_4_prod": ["P0", "P1", "P2", "P3"],
    }

    def __init__(self):
        self._catalog: Dict[str, QualityRule] = build_full_rule_catalog()

    @property
    def catalog(self) -> Dict[str, QualityRule]:
        return self._catalog

    def get_rule(self, rule_id: str) -> Optional[QualityRule]:
        return self._catalog.get(rule_id)

    def get_policy_for_task(
        self,
        task_description: str = "",
        modified_files: Optional[List[str]] = None,
        technologies: Optional[List[str]] = None,
        stage: Optional[str] = None,
        rollout_phase: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Implements `quality.get_policy` (Stage 1: Before Coding & Risk Profiling).
        Selects only the relevant rules based on modified components, languages, technology stack,
        and optional Section 10 rollout phase (`etap_1_p0` .. `etap_4_prod`).
        """
        files = modified_files or []
        active_techs = {t.lower() for t in (technologies or ["postgresql", "redis", "docker", "kubernetes"])}
        lower_desc = task_description.lower()
        lower_files = " ".join(f.lower() for f in files)
        combined_context = f"{lower_desc} {lower_files}"
        allowed_priorities = set(self.ROLLOUT_PHASES.get(rollout_phase or "etap_4_prod", ["P0", "P1", "P2", "P3"]))

        # Detect if change is purely cosmetic UI (e.g. button color change)
        is_cosmetic_ui_only = (
            bool(files)
            and all(f.endswith((".css", ".scss", ".less")) for f in files)
            and not any(k in lower_desc for k in ("auth", "order", "api", "db", "sql", "tenant", "price"))
        )

        selected_rules: List[QualityRule] = []
        mandatory_check_domains: List[str] = []

        if is_cosmetic_ui_only:
            # Cosmetic change: only XSS/CSP/UI freeze & basic secrets scan, NO DB transaction isolation tests
            cosmetic_ids = ["RAE-SEC-002", "RAE-SEC-010", "RAE-SEC-020", "RAE-SEC-208"]
            selected_rules = [self._catalog[rid] for rid in cosmetic_ids if rid in self._catalog]
            mandatory_check_domains = ["xss_csp", "secrets_scan"]
            risk_level = "LOW"
        else:
            # Always include core P0 security gates
            core_p0_ids = [
                "RAE-SEC-001",  # SQL Injection
                "RAE-SEC-002",  # XSS
                "RAE-SEC-005",  # SSRF
                "RAE-SEC-006",  # IDOR / Cross-tenant object access
                "RAE-SEC-007",  # Path Traversal
                "RAE-SEC-008",  # Mass Assignment
                "RAE-SEC-013",  # Server-Side Authorization
                "RAE-SEC-014",  # Row-Level Security
                "RAE-SEC-017",  # Secrets Management
                "RAE-SEC-020",  # Secret Scanning
                "RAE-SEC-033",  # File Upload Validation
                "RAE-SEC-199",  # AI Prompt Injection
                "RAE-SEC-201",  # Tenant Isolation Testing
                "RAE-SEC-208",  # Agent Self-Modification Protection
                "RAE-SEC-210",  # Audit Trail Integrity
            ]
            selected_ids = set(core_p0_ids)
            mandatory_check_domains.extend(["authorization", "tenant_isolation", "secrets_scan", "sast"])

            # Orders / Checkout / API / Pricing context
            if any(k in combined_context for k in ("order", "zamow", "cart", "koszyk", "price", "calc", "api", "controller", "endpoint")):
                selected_ids.update([
                    "RAE-SEC-048",  # Transactions
                    "RAE-SEC-049",  # ACID
                    "RAE-SEC-050",  # Isolation Levels
                    "RAE-SEC-090",  # Race Conditions
                    "RAE-SEC-128",  # OpenAPI Specs
                    "RAE-SEC-129",  # Backward Compatibility
                    "RAE-SEC-202",  # Business Logic Security
                    "RAE-EDT-001",  # Project/Page/Asset/Order Auth
                    "RAE-EDT-005",  # Production Parameter Validation
                ])
                mandatory_check_domains.extend(["transactions", "openapi_compatibility", "order_regression", "business_logic"])

            # Editor / DTP / PDF / Canvas / Upload context
            if any(k in combined_context for k in ("editor", "pdf", "dtp", "svg", "image", "upload", "canvas", "scene", "bleed", "exif")):
                for edt_rule in RAE_EDITOR_SECURITY_RULES:
                    selected_ids.add(edt_rule.id)
                mandatory_check_domains.extend(["editor_security", "file_upload_security", "race_conditions"])

            # Database / Migration context
            if any(k in combined_context for k in ("migration", "schema", "sql", "db", "database", "model", "repository", "query")):
                selected_ids.update([
                    "RAE-SEC-041",  # Indexes
                    "RAE-SEC-043",  # N+1 Queries
                    "RAE-SEC-046",  # Database Migrations
                    "RAE-SEC-047",  # Down Migrations
                    "RAE-SEC-048",  # Transactions
                    "RAE-SEC-052",  # Optimistic Locking
                    "RAE-SEC-056",  # Foreign Keys
                ])
                if "postgresql" in active_techs:
                    selected_ids.add("RAE-SEC-068")  # Postgres VACUUM (only when Postgres is active)
                mandatory_check_domains.append("database_integrity")

            # Infrastructure / Docker / K8s / CI context
            if any(k in combined_context for k in ("dockerfile", "docker-compose", "k8s", "helm", "values.yaml", "ci", "deploy", "infra")):
                selected_ids.update([
                    "RAE-SEC-141",  # Health Checks
                    "RAE-SEC-142",  # Liveness vs Readiness Probes
                    "RAE-SEC-143",  # Graceful Shutdown
                    "RAE-SEC-190",  # Multi-Stage Builds
                    "RAE-SEC-191",  # Non-Root Containers
                    "RAE-SEC-192",  # Image Scanning
                    "RAE-SEC-193",  # Resource Requests & Limits
                    "RAE-SEC-194",  # Pod Disruption Budgets
                    "RAE-SEC-195",  # Semantic Versioning
                    "RAE-SEC-196",  # Lockfiles
                    "RAE-SEC-198",  # Branch Protection
                ])
                mandatory_check_domains.append("infrastructure_containers")

            # Filter out rules requiring a technology that is NOT in active_techs or outside rollout phase
            for rid in sorted(selected_ids):
                rule = self._catalog.get(rid)
                if not rule:
                    continue
                req_techs = set(rule.applies_to.technologies)
                if req_techs and not req_techs.intersection(active_techs):
                    continue
                if rule.priority.value not in allowed_priorities:
                    continue
                if stage and rule.stage.value != stage and rule.priority != ModulePriority.P0:
                    continue
                selected_rules.append(rule)

            risk_level = "CRITICAL" if any(r.severity.value == "critical" for r in selected_rules) else "HIGH"

        return {
            "task_description": task_description,
            "modified_files": files,
            "active_technologies": sorted(list(active_techs)),
            "rollout_phase": rollout_phase or "etap_4_prod",
            "allowed_priorities": sorted(list(allowed_priorities)),
            "baseline_policy": "zero_tolerance_for_new_code_baseline_debt_tracked_separately",
            "is_cosmetic_ui_only": is_cosmetic_ui_only,
            "risk_level": risk_level,
            "mandatory_domains": sorted(list(set(mandatory_check_domains))),
            "selected_rules_count": len(selected_rules),
            "total_catalog_rules": len(self._catalog),
            "rules": [r.model_dump() for r in selected_rules],
            "agent_constraints": {
                "can_disable_mandatory_controls": False,
                "can_self_approve_exceptions": False,
                "can_modify_security_tests": False,
                "requires_verifiable_evidence": True,
            },
        }

    def validate_rule_evidence(self, rule_id: str, evidence: EvidenceItem) -> Dict[str, Any]:
        """
        Enforces Section 5:
        'Samo stwierdzenie agenta "sprawdziłem bezpieczeństwo" nie może być dowodem spełnienia reguły.
        Dowodem powinien być wynik skanera, testu, analiza przepływu danych lub zatwierdzony przegląd.'
        """
        rule = self._catalog.get(rule_id)
        if not rule:
            return {"valid": False, "reason": f"Unknown rule_id: {rule_id}"}

        has_concrete_proof = any([
            bool(evidence.test_result),
            bool(evidence.scanner_output),
            bool(evidence.data_flow_trace),
            bool(evidence.approved_review_id),
        ]) and evidence.verified_by_tool

        if not has_concrete_proof:
            return {
                "valid": False,
                "rule_id": rule_id,
                "reason": (
                    "REJECTED: Unverified agent statement is not valid evidence. "
                    "Must provide verifiable scanner output, test execution result, data-flow trace, or approved review."
                ),
            }

        missing_fields = []
        for req_field in rule.evidence_required:
            val = getattr(evidence, req_field, None)
            if not val:
                missing_fields.append(req_field)

        if missing_fields:
            return {
                "valid": False,
                "rule_id": rule_id,
                "reason": f"Missing required evidence fields for {rule_id}: {', '.join(missing_fields)}",
                "missing_fields": missing_fields,
            }

        return {
            "valid": True,
            "rule_id": rule_id,
            "reason": "Evidence verified by independent tool/test.",
        }

    def check_agent_tampering(
        self,
        agent_id: str,
        modified_files: List[str],
        requested_override: bool = False,
        disable_rules: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """
        Enforces Section 6 & 11 (RAE-SEC-208: Agent Self-Modification Protection).
        Agents cannot disable mandatory rules, self-accept exceptions, or modify quality gates.
        """
        violations = []
        if requested_override:
            violations.append(f"Agent '{agent_id}' attempted unauthorized quality gate override.")
        if disable_rules:
            violations.append(f"Agent '{agent_id}' attempted to disable mandatory rules: {disable_rules}")

        for f in modified_files:
            norm = f.replace("\\", "/")
            if any(p in norm for p in self.PROTECTED_QUALITY_PATHS):
                violations.append(f"Agent '{agent_id}' attempted to modify protected quality governance path: {f}")

        return {
            "tamper_detected": len(violations) > 0,
            "rule_id": "RAE-SEC-208",
            "enforcement": "BLOCK" if violations else "PASS",
            "violations": violations,
        }

    def generate_technical_manifest(self) -> Dict[str, Any]:
        """
        Implements Section 13 recommendation:
        Generates the complete technical implementation manifest mapping all 198 topics + 12 AI topics + 9 Editor rules.
        """
        modules_summary = []
        for mod in MODULE_DEFINITIONS:
            mod_rules = [r for r in self._catalog.values() if r.category == mod["id"] or r.module == mod["name"]]
            modules_summary.append({
                "module_id": mod["id"],
                "module_name": mod["name"],
                "priority": mod["priority"].value if hasattr(mod["priority"], "value") else str(mod["priority"]),
                "default_scanner": mod["default_scanner"],
                "rules_count": len(mod_rules),
            })

        return {
            "version": "2.0.0",
            "total_198_topics": len(ALL_198_TOPICS),
            "total_ai_saas_extensions": len(ADDITIONAL_AI_SAAS_TOPICS),
            "total_editor_security_rules": len(RAE_EDITOR_SECURITY_RULES),
            "total_rules_in_engine": len(self._catalog),
            "modules": modules_summary,
            "control_types": ["deterministic", "ai_semantic", "systemic"],
            "stages": ["before_coding", "during_work", "pre_merge", "pre_prod_post_deploy"],
        }
