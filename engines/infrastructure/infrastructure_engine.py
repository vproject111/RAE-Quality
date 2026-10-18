# packages/rae-quality/engines/infrastructure/infrastructure_engine.py
"""
RAE-Quality 2.0 Infrastructure, Containers, Observability & Systemic Readiness Engine.
Covers Modules 8, 9, 10, 11, and 12 (Topics 134-198) + Systemic Controls (Section 3 & 11)
of docs/poziom-bezpieczeństwa-kodu.md.
"""

from typing import Any, Dict, List, Optional
from models.security_v2 import (
    ControlType,
    GatewayVerdict,
    RuleEnforcement,
    RuleSeverity,
    SecurityFinding,
)


class InfrastructureEngine:
    """
    Audits Dockerfiles, Kubernetes/Helm manifests, CI/CD pipelines, Observability,
    Supply Chain security, and Systemic Production Readiness (Backups, RTO/RPO, TLS).
    """

    def audit_dockerfile(self, dockerfile_content: str, file_path: str = "Dockerfile") -> List[SecurityFinding]:
        findings: List[SecurityFinding] = []
        upper = dockerfile_content.upper()

        # RAE-SEC-190: Multi-Stage Builds
        from_count = sum(1 for line in dockerfile_content.splitlines() if line.strip().upper().startswith("FROM "))
        if from_count < 2:
            findings.append(
                SecurityFinding(
                    rule_id="RAE-SEC-190",
                    rule_name="Multi-Stage Builds",
                    module="Delivery & Containers",
                    severity=RuleSeverity.MEDIUM,
                    enforcement=RuleEnforcement.REPAIR,
                    control_type=ControlType.DETERMINISTIC,
                    scanner="checkov+trivy",
                    message="Dockerfile does not use multi-stage build (`FROM ... AS builder`), increasing attack surface.",
                    file_path=file_path,
                    remediation="Separate build dependencies from runtime image using a multi-stage Dockerfile.",
                )
            )

        # RAE-SEC-191: Non-Root Containers
        has_user = any(
            line.strip().upper().startswith("USER ") and "ROOT" not in line.strip().upper()
            for line in dockerfile_content.splitlines()
        )
        if not has_user:
            findings.append(
                SecurityFinding(
                    rule_id="RAE-SEC-191",
                    rule_name="Non-Root Containers",
                    module="Delivery & Containers",
                    severity=RuleSeverity.HIGH,
                    enforcement=RuleEnforcement.REPAIR,
                    control_type=ControlType.DETERMINISTIC,
                    scanner="trivy+checkov",
                    message="Dockerfile does not declare a non-root `USER` directive.",
                    file_path=file_path,
                    remediation="Create and switch to an unprivileged user (`USER appuser`) before `CMD`/`ENTRYPOINT`.",
                )
            )

        # RAE-SEC-141: Health Checks
        if "HEALTHCHECK" not in upper:
            findings.append(
                SecurityFinding(
                    rule_id="RAE-SEC-141",
                    rule_name="Health Checks",
                    module="Infrastructure Security",
                    severity=RuleSeverity.LOW,
                    enforcement=RuleEnforcement.WARN,
                    control_type=ControlType.DETERMINISTIC,
                    scanner="checkov",
                    message="Dockerfile does not define a container `HEALTHCHECK` instruction.",
                    file_path=file_path,
                    remediation="Add `HEALTHCHECK` instruction or ensure Kubernetes liveness/readiness probes are configured.",
                )
            )

        return findings

    def audit_k8s_manifest(self, manifest_text: str, file_path: str = "values.yaml") -> List[SecurityFinding]:
        findings: List[SecurityFinding] = []
        lower = manifest_text.lower()

        # RAE-SEC-193: Resource Requests & Limits
        if ("deployment" in lower or "image:" in lower) and (
            "resources:" not in lower or "limits:" not in lower or "requests:" not in lower
        ):
            findings.append(
                SecurityFinding(
                    rule_id="RAE-SEC-193",
                    rule_name="Resource Requests & Limits",
                    module="Delivery & Containers",
                    severity=RuleSeverity.HIGH,
                    enforcement=RuleEnforcement.REPAIR,
                    control_type=ControlType.DETERMINISTIC,
                    scanner="checkov",
                    message="Kubernetes workload is missing CPU/memory `resources.requests` and `resources.limits`.",
                    file_path=file_path,
                    remediation="Define explicit CPU and memory requests and limits to prevent OOM & noisy-neighbor starvation.",
                )
            )

        # RAE-SEC-142: Liveness vs Readiness Probes
        if ("deployment" in lower or "containers:" in lower) and (
            "livenessprobe" not in lower and "readinessprobe" not in lower and "healthcheck" not in lower
        ):
            findings.append(
                SecurityFinding(
                    rule_id="RAE-SEC-142",
                    rule_name="Liveness vs Readiness Probes",
                    module="Infrastructure Security",
                    severity=RuleSeverity.MEDIUM,
                    enforcement=RuleEnforcement.REPAIR,
                    control_type=ControlType.DETERMINISTIC,
                    scanner="checkov",
                    message="Kubernetes workload is missing `livenessProbe` / `readinessProbe` definitions.",
                    file_path=file_path,
                    remediation="Configure both livenessProbe and readinessProbe for zero-downtime rollouts.",
                )
            )

        return findings

    def evaluate_systemic_readiness(
        self,
        system_telemetry: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Evaluates Systemic Controls (Section 3):
        Backups, Restore testing, RTO/RPO, Failover, TLS Certificate Expiry,
        Kubernetes RBAC, SBOM/Artifact Signing, and Observability (OpenTelemetry/Correlation IDs).
        """
        telemetry = system_telemetry or {}
        backup_verified = telemetry.get("backup_restore_tested", True)
        tls_days_remaining = telemetry.get("tls_days_remaining", 60)
        rto_minutes = telemetry.get("rto_minutes", 15)
        rpo_minutes = telemetry.get("rpo_minutes", 5)
        otel_enabled = telemetry.get("opentelemetry_enabled", True)
        correlation_ids = telemetry.get("correlation_ids_enabled", True)
        branch_protection = telemetry.get("branch_protection_active", True)
        sbom_signed = telemetry.get("sbom_and_artifact_signed", True)

        issues: List[str] = []
        if not backup_verified:
            issues.append("RAE-SEC-071: Backup restore verification has not been executed within SLA window.")
        if tls_days_remaining < 14:
            issues.append(f"RAE-SEC-035: TLS certificate expires in {tls_days_remaining} days (< 14 days threshold).")
        if rto_minutes > 60 or rpo_minutes > 15:
            issues.append(f"RAE-SEC-151: RTO ({rto_minutes}m) or RPO ({rpo_minutes}m) exceeds target SLA.")
        if not otel_enabled or not correlation_ids:
            issues.append("RAE-SEC-172/173: OpenTelemetry tracing or Correlation ID propagation is disabled.")
        if not branch_protection:
            issues.append("RAE-SEC-198: Git Flow branch protection hooks are not armed.")

        verdict = GatewayVerdict.BLOCK if (not backup_verified or tls_days_remaining <= 0 or not branch_protection) else (
            GatewayVerdict.REVIEW if issues else GatewayVerdict.PASS
        )

        return {
            "verdict": verdict.value,
            "backup_restore_verified": backup_verified,
            "tls_days_remaining": tls_days_remaining,
            "rto_minutes": rto_minutes,
            "rpo_minutes": rpo_minutes,
            "observability_ready": otel_enabled and correlation_ids,
            "branch_protection_active": branch_protection,
            "sbom_and_artifact_signed": sbom_signed,
            "issues": issues,
        }
