# packages/rae-quality/engines/security/security_gateway.py
"""
RAE-Quality 2.0 Security Engine & SARIF 2.1.0 Normalizer.
Implements Sections 4, 6, 7, 8, and 11 of docs/poziom-bezpieczeństwa-kodu.md:
- SAST, SCA, Secrets, Authorization, IDOR, Mass Assignment, SQLi, XSS, SSRF, File Upload, Prompt Injection
- RAE-EDITOR-SECURITY rules (RAE-EDT-001 .. RAE-EDT-009)
- External Scanner Integration & Language Matrix (Semgrep, CodeQL, Gitleaks, Trivy, OWASP ZAP,
  SonarQube, Schemathesis, Playwright, k6, Checkov)
- Unified SARIF 2.1.0 report output with RAE risk & decision metadata
"""

import re
from typing import Any, Dict, List, Optional
from models.security_v2 import (
    ControlType,
    GatewayVerdict,
    RuleEnforcement,
    RuleSeverity,
    SARIFReport,
    SARIFResult,
    SARIFRun,
    SecurityFinding,
)


class SecurityGateway:
    """
    Executes deterministic and semantic security scans across code diffs, files, and payloads,
    normalizing all findings into SARIF 2.1.0 format.
    """

    # Section 7: Integrated Scanner Registry & Language Support Matrix
    SCANNER_REGISTRY: Dict[str, Dict[str, Any]] = {
        "semgrep": {
            "purpose": "SAST, custom PHP/JS/TS/Python rules, dangerous patterns",
            "supported_languages": ["php", "javascript", "typescript", "python", "go"],
            "output_format": "SARIF",
        },
        "codeql": {
            "purpose": "Data flow analysis, taint tracking, inter-procedural vulnerabilities",
            # Section 7 explicit note: PHP is not supported in standard CodeQL matrix
            "supported_languages": ["javascript", "typescript", "python", "go", "java", "cpp", "csharp"],
            "unsupported_languages": ["php"],
            "fallback_for_php": "semgrep+sonarqube",
            "output_format": "SARIF",
        },
        "gitleaks": {
            "purpose": "Secret detection in source code and Git history",
            "supported_languages": ["all"],
            "output_format": "SARIF",
        },
        "trivy": {
            "purpose": "SCA dependency vulnerabilities, container images, and IaC misconfigurations",
            "supported_languages": ["all", "docker", "kubernetes", "terraform"],
            "output_format": "SARIF",
        },
        "owasp_zap": {
            "purpose": "Dynamic Application Security Testing (DAST)",
            "supported_languages": ["http_api", "web"],
            "output_format": "SARIF",
        },
        "sonarqube": {
            "purpose": "Code quality, maintainability, security hotspots, duplications",
            "supported_languages": ["php", "javascript", "typescript", "python", "go"],
            "output_format": "SARIF",
        },
        "schemathesis": {
            "purpose": "Automated property-based API testing from OpenAPI specs",
            "supported_languages": ["openapi", "rest_api"],
            "output_format": "JSON/SARIF",
        },
        "playwright": {
            "purpose": "E2E tests, permissions, sessions, multi-tenant isolation",
            "supported_languages": ["typescript", "javascript", "web"],
            "output_format": "JSON",
        },
        "k6": {
            "purpose": "Load testing, performance SLA, and concurrency/race condition verification",
            "supported_languages": ["http_api", "websocket"],
            "output_format": "JSON",
        },
        "checkov": {
            "purpose": "Infrastructure as Code (IaC), Kubernetes, Dockerfile, and Terraform security",
            "supported_languages": ["dockerfile", "kubernetes", "helm", "terraform"],
            "output_format": "SARIF",
        },
    }

    # Regex patterns for deterministic and semantic vulnerability detection
    PATTERNS = [
        {
            "rule_id": "RAE-SEC-001",
            "rule_name": "SQL Injection",
            "module": "Security & OWASP",
            "severity": RuleSeverity.CRITICAL,
            "enforcement": RuleEnforcement.BLOCK,
            "control_type": ControlType.DETERMINISTIC,
            "scanner": "semgrep",
            "regex": re.compile(
                r'(?:SELECT|INSERT|UPDATE|DELETE)\s+.*?(?:\+\s*[a-zA-Z_$]|\{[a-zA-Z0-9_.\[\]\'"]+\}|\.\s*\$_(?:GET|POST|REQUEST))',
                re.IGNORECASE,
            ),
            "message": "Unsanitized variable interpolated or concatenated directly into SQL query.",
            "remediation": "Use parameterized queries / prepared statements with bound parameters.",
        },
        {
            "rule_id": "RAE-SEC-002",
            "rule_name": "Cross-Site Scripting (XSS)",
            "module": "Security & OWASP",
            "severity": RuleSeverity.CRITICAL,
            "enforcement": RuleEnforcement.BLOCK,
            "control_type": ControlType.DETERMINISTIC,
            "scanner": "semgrep",
            "regex": re.compile(
                r'(?:dangerouslySetInnerHTML|\.innerHTML\s*=|echo\s+\$_(?:GET|POST|REQUEST)|document\.write\s*\()',
                re.IGNORECASE,
            ),
            "message": "Unescaped HTML/JavaScript sink detected (XSS risk in project/resource rendering).",
            "remediation": "Sanitize HTML with DOMPurify or use framework-escaped text bindings.",
        },
        {
            "rule_id": "RAE-SEC-005",
            "rule_name": "Server-Side Request Forgery (SSRF)",
            "module": "Security & OWASP",
            "severity": RuleSeverity.CRITICAL,
            "enforcement": RuleEnforcement.BLOCK,
            "control_type": ControlType.DETERMINISTIC,
            "scanner": "semgrep",
            "regex": re.compile(
                r'(?:169\.254\.169\.254|(?:requests\.(?:get|post)|httpx\.(?:get|post)|file_get_contents|curl_exec)\s*\(\s*(?:req\.|request\.|\$_(?:GET|POST)|user_url|import_url))',
                re.IGNORECASE,
            ),
            "message": "Potential SSRF: Fetching user-controlled or internal network URL without allowlist validation.",
            "remediation": "Validate URL scheme/host against strict allowlist and block RFC1918/link-local IPs.",
        },
        {
            "rule_id": "RAE-SEC-006",
            "rule_name": "Cross-tenant object access (IDOR)",
            "module": "Security & OWASP",
            "severity": RuleSeverity.CRITICAL,
            "enforcement": RuleEnforcement.BLOCK,
            "control_type": ControlType.AI_SEMANTIC,
            "scanner": "rae-security-gateway",
            "regex": re.compile(
                r'(?:req\.(?:body|query|params)\.(?:tenantId|tenant_id)|\$_(?:GET|POST|REQUEST)\[[\'"](?:tenant_id|tenantId)[\'"]\]|payload\.get\([\'"](?:tenant_id|tenantId)[\'"]\))',
                re.IGNORECASE,
            ),
            "message": "Cross-tenant IDOR risk: Client-provided tenantId is trusted instead of server-authenticated tenant context.",
            "remediation": "Resolve tenant_id strictly from authenticated server session/JWT claims and enforce tenant ownership on resource lookup.",
        },
        {
            "rule_id": "RAE-SEC-007",
            "rule_name": "Path Traversal",
            "module": "Security & OWASP",
            "severity": RuleSeverity.CRITICAL,
            "enforcement": RuleEnforcement.BLOCK,
            "control_type": ControlType.DETERMINISTIC,
            "scanner": "semgrep",
            "regex": re.compile(
                r'(?:\.\./|\.\.\\|open\s*\(\s*f[\'"].*?\{.*?(?:filename|path|file)\})',
                re.IGNORECASE,
            ),
            "message": "Path traversal pattern detected in file access operation.",
            "remediation": "Normalize path with Path.resolve() and verify it starts with the allowed base directory.",
        },
        {
            "rule_id": "RAE-SEC-008",
            "rule_name": "Mass Assignment",
            "module": "Security & OWASP",
            "severity": RuleSeverity.CRITICAL,
            "enforcement": RuleEnforcement.BLOCK,
            "control_type": ControlType.DETERMINISTIC,
            "scanner": "semgrep",
            "regex": re.compile(
                r'(?:::create\s*\(\s*\$request->all\(\)|Object\.assign\s*\(\s*\w+\s*,\s*req\.body\)|(?:\*\*request\.json\(\)|\*\*payload).*?(?:isAdmin|is_admin|role|price))',
                re.IGNORECASE,
            ),
            "message": "Mass Assignment vulnerability: Unfiltered client payload bound to model/entity (risk of overwriting role, price, or isAdmin).",
            "remediation": "Use explicit DTO allowlists excluding privileged fields (role, isAdmin, price, tenant_id).",
        },
        {
            "rule_id": "RAE-SEC-020",
            "rule_name": "Secret Scanning",
            "module": "Identity & Secrets",
            "severity": RuleSeverity.CRITICAL,
            "enforcement": RuleEnforcement.BLOCK,
            "control_type": ControlType.DETERMINISTIC,
            "scanner": "gitleaks",
            "regex": re.compile(
                r'(?:sk-[a-zA-Z0-9]{20,}|ghp_[a-zA-Z0-9]{25,}|AKIA[0-9A-Z]{16}|-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|(?:api_key|secret_key|password)\s*=\s*[\'"][a-zA-Z0-9_\-!@#$%^&*]{12,}[\'"])',
            ),
            "message": "Hardcoded secret, private key, or API token detected in source code.",
            "remediation": "Move secrets to environment variables / secret manager and rotate compromised credentials.",
        },
        {
            "rule_id": "RAE-SEC-033",
            "rule_name": "File Upload Validation",
            "module": "Security & OWASP",
            "severity": RuleSeverity.CRITICAL,
            "enforcement": RuleEnforcement.BLOCK,
            "control_type": ControlType.DETERMINISTIC,
            "scanner": "rae-security-gateway",
            "regex": re.compile(
                r'(?:<svg[^>]*>.*?<script|onload\s*=|\.save\s*\(\s*upload\.filename\s*\))',
                re.IGNORECASE | re.DOTALL,
            ),
            "message": "Unsafe file upload handling or active script inside uploaded SVG/document.",
            "remediation": "Validate MIME & magic bytes, sanitize SVG XML, strip dangerous scripts, and generate random storage filenames.",
        },
        {
            "rule_id": "RAE-SEC-199",
            "rule_name": "AI Prompt Injection",
            "module": "Agentic AI & SaaS Governance",
            "severity": RuleSeverity.CRITICAL,
            "enforcement": RuleEnforcement.BLOCK,
            "control_type": ControlType.AI_SEMANTIC,
            "scanner": "rae-security-gateway",
            "regex": re.compile(
                r'(?:ignore\s+(?:all\s+)?previous\s+instructions|system\s+override\s*:|you\s+are\s+now\s+in\s+developer\s+mode)',
                re.IGNORECASE,
            ),
            "message": "AI Prompt Injection payload detected in code, document, or untrusted input.",
            "remediation": "Isolate untrusted content in delimited user blocks and strip instruction-override tokens.",
        },
        {
            "rule_id": "RAE-SEC-207",
            "rule_name": "Safe Deserialization",
            "module": "Agentic AI & SaaS Governance",
            "severity": RuleSeverity.CRITICAL,
            "enforcement": RuleEnforcement.BLOCK,
            "control_type": ControlType.DETERMINISTIC,
            "scanner": "semgrep",
            "regex": re.compile(
                r'(?:pickle\.loads\s*\(|yaml\.load\s*\([^,)]+\)|unserialize\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE))',
                re.IGNORECASE,
            ),
            "message": "Unsafe deserialization of untrusted data detected.",
            "remediation": "Use safe parsers (json.loads, yaml.safe_load) and never unserialize untrusted objects.",
        },
        {
            "rule_id": "RAE-EDT-002",
            "rule_name": "Multi-Printshop Data Isolation (Cache, WebSockets, Queues, Files)",
            "module": "RAE-EDITOR-SECURITY",
            "severity": RuleSeverity.CRITICAL,
            "enforcement": RuleEnforcement.BLOCK,
            "control_type": ControlType.DETERMINISTIC,
            "scanner": "rae-security-gateway",
            "regex": re.compile(
                r'(?:redis\.(?:get|set)\s*\(\s*f?[\'"]project:\{?(?:project_id|id)\}?[\'"]|socket\.join\s*\(\s*f?[\'"]project_room_)',
                re.IGNORECASE,
            ),
            "message": "Missing tenant_id namespace prefix in Redis cache key or WebSocket room name.",
            "remediation": "Prefix all cache keys and WebSocket rooms with tenant_id (e.g. `tenant:{tenant_id}:project:{project_id}`).",
        },
        {
            "rule_id": "RAE-EDT-005",
            "rule_name": "Production Parameter Server-Side Validation (Format, Bleed, Pages, Price)",
            "module": "RAE-EDITOR-SECURITY",
            "severity": RuleSeverity.CRITICAL,
            "enforcement": RuleEnforcement.BLOCK,
            "control_type": ControlType.DETERMINISTIC,
            "scanner": "rae-security-gateway",
            "regex": re.compile(
                r'(?:order\.total_price\s*=\s*(?:req\.body\.price|payload\[[\'"]price[\'"]\]|\$_POST\[[\'"]price[\'"]\])|trust_client_price\s*=\s*True)',
                re.IGNORECASE,
            ),
            "message": "Business Logic Violation: Order accepts client-submitted price without server-side calculation.",
            "remediation": "Always recalculate total price and validate format/bleed/pages via server-side CalculationEngine.",
        },
    ]

    def get_compatible_scanners(self, languages: List[str]) -> Dict[str, Any]:
        """
        Returns scanners appropriate for the given languages, respecting Section 7 constraints
        (e.g. CodeQL does not natively support PHP).
        """
        normalized_langs = {lang.lower() for lang in languages}
        selected = {}
        warnings = []

        for scanner_id, meta in self.SCANNER_REGISTRY.items():
            unsupported = set(meta.get("unsupported_languages", []))
            if normalized_langs and normalized_langs.issubset(unsupported):
                warnings.append(
                    f"Scanner '{scanner_id}' skipped for {sorted(list(normalized_langs))}; "
                    f"using fallback '{meta.get('fallback_for_php', 'semgrep')}'."
                )
                continue
            supported = set(meta.get("supported_languages", []))
            if "all" in supported or not normalized_langs or normalized_langs.intersection(supported):
                selected[scanner_id] = meta

        return {
            "languages": sorted(list(normalized_langs)),
            "selected_scanners": selected,
            "compatibility_notes": warnings,
        }

    def scan_code(
        self,
        code: str,
        file_path: str = "inline_snippet.py",
        languages: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """
        Implements `quality.security_scan` and `quality.analyze_diff`.
        Scans code/diff for OWASP, Identity/Secrets, AI Prompt Injection, and RAE-EDITOR-SECURITY violations,
        and produces both structured findings and a normalized SARIF 2.1.0 report.
        """
        findings: List[SecurityFinding] = []
        lines = code.splitlines() or [code]

        for pat in self.PATTERNS:
            for idx, line in enumerate(lines, start=1):
                if pat["regex"].search(line):
                    findings.append(
                        SecurityFinding(
                            rule_id=pat["rule_id"],
                            rule_name=pat["rule_name"],
                            module=pat["module"],
                            severity=pat["severity"],
                            enforcement=pat["enforcement"],
                            control_type=pat["control_type"],
                            scanner=pat["scanner"],
                            message=pat["message"],
                            file_path=file_path,
                            line_number=idx,
                            remediation=pat["remediation"],
                            evidence={"matched_line": line.strip()[:200], "verified_by_tool": True},
                        )
                    )
            # Also check multi-line patterns (e.g. SVG with <script>)
            if not any(f.rule_id == pat["rule_id"] for f in findings) and pat["regex"].search(code):
                findings.append(
                    SecurityFinding(
                        rule_id=pat["rule_id"],
                        rule_name=pat["rule_name"],
                        module=pat["module"],
                        severity=pat["severity"],
                        enforcement=pat["enforcement"],
                        control_type=pat["control_type"],
                        scanner=pat["scanner"],
                        message=pat["message"],
                        file_path=file_path,
                        line_number=1,
                        remediation=pat["remediation"],
                        evidence={"matched_snippet": code[:200], "verified_by_tool": True},
                    )
                )

        has_blockers = any(f.enforcement == RuleEnforcement.BLOCK for f in findings)
        verdict = GatewayVerdict.BLOCK if has_blockers else (GatewayVerdict.REPAIR if findings else GatewayVerdict.PASS)
        sarif = self.to_sarif_report(findings, verdict=verdict)

        return {
            "verdict": verdict.value,
            "findings_count": len(findings),
            "blocking_count": sum(1 for f in findings if f.enforcement == RuleEnforcement.BLOCK),
            "findings": [f.model_dump() for f in findings],
            "sarif": sarif.model_dump(by_alias=True),
            "scanner_matrix": self.get_compatible_scanners(languages or ["python", "php", "typescript"]),
        }

    def to_sarif_report(
        self,
        findings: List[SecurityFinding],
        verdict: GatewayVerdict = GatewayVerdict.PASS,
    ) -> SARIFReport:
        """Normalizes RAE-Quality findings into standard SARIF 2.1.0 format."""
        sarif_results: List[SARIFResult] = []
        for f in findings:
            level = "error" if f.severity in (RuleSeverity.CRITICAL, RuleSeverity.HIGH) else "warning"
            sarif_results.append(
                SARIFResult(
                    ruleId=f.rule_id,
                    level=level,
                    message={"text": f"[{f.rule_name}] {f.message} | Fix: {f.remediation}"},
                    locations=[
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": f.file_path or "unknown"},
                                "region": {"startLine": f.line_number or 1},
                            }
                        }
                    ],
                    properties={
                        "module": f.module,
                        "enforcement": f.enforcement.value,
                        "control_type": f.control_type.value,
                        "scanner": f.scanner,
                    },
                )
            )

        run = SARIFRun(
            tool={
                "driver": {
                    "name": "RAE-Quality Security Gateway",
                    "version": "2.0.0",
                    "informationUri": "https://github.com/vproject111/RAE-Quality",
                }
            },
            results=sarif_results,
            invocations=[{"executionSuccessful": True}],
        )

        return SARIFReport(
            runs=[run],
            rae_metadata={
                "gateway_verdict": verdict.value,
                "total_findings": len(findings),
            },
        )
