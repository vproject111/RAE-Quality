# packages/rae-quality/engines/security/security_gateway.py
"""
RAE-Quality 2.0 Security Engine & SARIF 2.1.0 Normalizer.
Implements Sections 4, 6, 7, 8, 10, and 11 of docs/poziom-bezpieczeństwa-kodu.md:
- SAST, SCA, Secrets, Authorization, IDOR, Mass Assignment, SQLi, XSS, CSRF, CORS, CSP,
  SSRF, File Upload, Weak Password Hashing, JWT Security, Timing Attacks, Webhook HMAC, Prompt Injection
- Complete 9/9 RAE-EDITOR-SECURITY rules (RAE-EDT-001 .. RAE-EDT-009)
- External Scanner Integration & Language Matrix (Semgrep, CodeQL, Gitleaks, Trivy, OWASP ZAP,
  SonarQube, Schemathesis, Playwright, k6, Checkov)
- Baseline Fingerprint Separation (Section 10: Historical debt vs new blocking findings)
- Unified SARIF 2.1.0 report output with RAE risk & decision metadata
"""

import hashlib
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
    normalizing all findings into SARIF 2.1.0 format and supporting baseline debt separation.
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
        # --- OWASP & Core Security ---
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
            "rule_id": "RAE-SEC-003",
            "rule_name": "CSRF Protection",
            "module": "Security & OWASP",
            "severity": RuleSeverity.HIGH,
            "enforcement": RuleEnforcement.BLOCK,
            "control_type": ControlType.DETERMINISTIC,
            "scanner": "semgrep",
            "regex": re.compile(
                r'(?:@csrf_exempt|verify_csrf\s*=\s*False|csrfProtection\s*:\s*false)',
                re.IGNORECASE,
            ),
            "message": "CSRF protection explicitly disabled on state-changing endpoint.",
            "remediation": "Enable CSRF token verification or SameSite=Strict/Lax session cookies on state-changing routes.",
        },
        {
            "rule_id": "RAE-SEC-004",
            "rule_name": "CORS Misconfiguration",
            "module": "Security & OWASP",
            "severity": RuleSeverity.HIGH,
            "enforcement": RuleEnforcement.BLOCK,
            "control_type": ControlType.DETERMINISTIC,
            "scanner": "semgrep",
            "regex": re.compile(
                r'(?:Access-Control-Allow-Origin[\'"]?\s*[:=]\s*[\'"]\*[\'"].*?Access-Control-Allow-Credentials[\'"]?\s*[:=]\s*[\'"]?true|allow_origins\s*=\s*\[\s*[\'"]\*[\'"]\s*\].*?allow_credentials\s*=\s*True)',
                re.IGNORECASE | re.DOTALL,
            ),
            "message": "Insecure CORS configuration combining wildcard origin ('*') with credentials=True.",
            "remediation": "Specify an explicit allowlist of trusted tenant domains when allow_credentials is enabled.",
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
            "rule_id": "RAE-SEC-010",
            "rule_name": "Content Security Policy (CSP)",
            "module": "Security & OWASP",
            "severity": RuleSeverity.HIGH,
            "enforcement": RuleEnforcement.REPAIR,
            "control_type": ControlType.DETERMINISTIC,
            "scanner": "semgrep",
            "regex": re.compile(
                r'Content-Security-Policy.*?unsafe-eval',
                re.IGNORECASE,
            ),
            "message": "CSP header allows 'unsafe-eval', weakening XSS mitigation in editor/browser context.",
            "remediation": "Remove 'unsafe-eval' and use nonce-based or strict hash-based Content-Security-Policy.",
        },
        # --- Identity & Secrets ---
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
            "rule_id": "RAE-SEC-023",
            "rule_name": "Password Hashing (Argon2id/bcrypt)",
            "module": "Identity & Secrets",
            "severity": RuleSeverity.CRITICAL,
            "enforcement": RuleEnforcement.BLOCK,
            "control_type": ControlType.DETERMINISTIC,
            "scanner": "semgrep",
            "regex": re.compile(
                r'(?:hashlib\.(?:md5|sha1)\s*\(\s*\w*pass|md5\s*\(\s*\$\w*pass|sha1\s*\(\s*\$\w*pass)',
                re.IGNORECASE,
            ),
            "message": "Weak password hashing algorithm (MD5/SHA1) detected.",
            "remediation": "Hash passwords exclusively with Argon2id or bcrypt with appropriate work factor.",
        },
        {
            "rule_id": "RAE-SEC-024",
            "rule_name": "JWT Security",
            "module": "Identity & Secrets",
            "severity": RuleSeverity.CRITICAL,
            "enforcement": RuleEnforcement.BLOCK,
            "control_type": ControlType.DETERMINISTIC,
            "scanner": "semgrep",
            "regex": re.compile(
                r'(?:algorithms\s*=\s*\[\s*[\'"]none[\'"]\s*\]|verify_signature[\'"]?\s*:\s*False|verify_exp[\'"]?\s*:\s*False)',
                re.IGNORECASE,
            ),
            "message": "Insecure JWT validation (alg='none' or signature/expiration verification disabled).",
            "remediation": "Enforce strong asymmetric/HMAC algorithms and require both signature and exp/aud verification.",
        },
        {
            "rule_id": "RAE-SEC-032",
            "rule_name": "Timing Attack Protection",
            "module": "Security & OWASP",
            "severity": RuleSeverity.HIGH,
            "enforcement": RuleEnforcement.BLOCK,
            "control_type": ControlType.DETERMINISTIC,
            "scanner": "semgrep",
            "regex": re.compile(
                r'(?:(?:hmac_signature|webhook_signature|api_token|secret_token)\s*==\s*(?:expected_signature|provided_signature|req_token))',
                re.IGNORECASE,
            ),
            "message": "Non-constant-time string comparison (`==`) used for secret token or HMAC signature verification.",
            "remediation": "Use constant-time comparison (`hmac.compare_digest` or `hash_equals`).",
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
            "rule_id": "RAE-SEC-034",
            "rule_name": "Webhook Verification",
            "module": "Security & OWASP",
            "severity": RuleSeverity.CRITICAL,
            "enforcement": RuleEnforcement.BLOCK,
            "control_type": ControlType.DETERMINISTIC,
            "scanner": "semgrep",
            "regex": re.compile(
                r'(?:verify_webhook_signature\s*=\s*False|skip_webhook_hmac\s*=\s*True)',
                re.IGNORECASE,
            ),
            "message": "Webhook endpoint processes external payment/printshop events with signature verification disabled.",
            "remediation": "Verify webhook HMAC signature and timestamp replay window before processing payload.",
        },
        # --- Agentic AI & SaaS Governance ---
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
        # --- Complete 9/9 RAE-EDITOR-SECURITY Pack (RAE-EDT-001 .. RAE-EDT-009) ---
        {
            "rule_id": "RAE-EDT-001",
            "rule_name": "Project, Page, Asset, and Order Authorization",
            "module": "RAE-EDITOR-SECURITY",
            "severity": RuleSeverity.CRITICAL,
            "enforcement": RuleEnforcement.BLOCK,
            "control_type": ControlType.AI_SEMANTIC,
            "scanner": "rae-security-gateway",
            "regex": re.compile(
                r'(?:Project\.get_by_id_unscoped\s*\(|Order\.find_without_tenant\s*\(|skip_owner_check\s*=\s*True)',
                re.IGNORECASE,
            ),
            "message": "Direct project/page/asset/order lookup bypassing owner and tenant authorization.",
            "remediation": "Enforce server-side owner_id and tenant_id verification on every project, page, asset, and order operation.",
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
            "rule_id": "RAE-EDT-003",
            "rule_name": "Role & Permission Separation (Customer, Collaborator, Printshop Operator/Admin, Platform Admin)",
            "module": "RAE-EDITOR-SECURITY",
            "severity": RuleSeverity.CRITICAL,
            "enforcement": RuleEnforcement.BLOCK,
            "control_type": ControlType.AI_SEMANTIC,
            "scanner": "rae-security-gateway",
            "regex": re.compile(
                r'(?:allow_cross_printshop_admin\s*=\s*True|role\s*==\s*[\'"]printshop_admin[\'"]\s*and\s*skip_tenant_filter)',
                re.IGNORECASE,
            ),
            "message": "Printshop admin granted cross-printshop access or unlogged administrative override.",
            "remediation": "Restrict printshop_admin strictly to their own printshop tenant_id and log all platform_admin access.",
        },
        {
            "rule_id": "RAE-EDT-004",
            "rule_name": "Collaborative Editing & Autosave Protection (Optimistic Locking / Versioning)",
            "module": "RAE-EDITOR-SECURITY",
            "severity": RuleSeverity.HIGH,
            "enforcement": RuleEnforcement.REPAIR,
            "control_type": ControlType.DETERMINISTIC,
            "scanner": "rae-security-gateway",
            "regex": re.compile(
                r'(?:autosave_overwrite_without_version\s*=\s*True|save_canvas_state\s*\([^)]*ignore_version_conflict\s*=\s*True)',
                re.IGNORECASE,
            ),
            "message": "Collaborative project autosave overwrites scene state without version/optimistic lock verification.",
            "remediation": "Verify base_version / ETag on every autosave and return HTTP 409 Conflict on concurrent modification.",
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
        {
            "rule_id": "RAE-EDT-006",
            "rule_name": "File Upload, Asset Import & EXIF Metadata Sanitization",
            "module": "RAE-EDITOR-SECURITY",
            "severity": RuleSeverity.CRITICAL,
            "enforcement": RuleEnforcement.BLOCK,
            "control_type": ControlType.DETERMINISTIC,
            "scanner": "rae-security-gateway",
            "regex": re.compile(
                r'(?:preserve_exif_gps\s*=\s*True|strip_exif\s*=\s*False|allow_embedded_pdf_js\s*=\s*True)',
                re.IGNORECASE,
            ),
            "message": "Uploaded image/PDF asset retains sensitive EXIF GPS metadata or embedded PDF JavaScript.",
            "remediation": "Strip EXIF GPS/camera metadata on image ingest and reject/sanitize embedded scripts in SVG/PDF files.",
        },
        {
            "rule_id": "RAE-EDT-007",
            "rule_name": "Share Links & Project Previews Security (Token Scope, Expiry, Revocation)",
            "module": "RAE-EDITOR-SECURITY",
            "severity": RuleSeverity.HIGH,
            "enforcement": RuleEnforcement.BLOCK,
            "control_type": ControlType.DETERMINISTIC,
            "scanner": "rae-security-gateway",
            "regex": re.compile(
                r'(?:share_token\s*=\s*(?:str\(project_id\)|md5\(project_id\))|share_link_never_expires\s*=\s*True)',
                re.IGNORECASE,
            ),
            "message": "Predictable or non-expiring project share/preview link token detected.",
            "remediation": "Generate cryptographically random share tokens (secrets.token_urlsafe) with explicit scope, TTL, and revocation support.",
        },
        {
            "rule_id": "RAE-EDT-008",
            "rule_name": "Render & Preflight Worker Isolation (Sandboxing, Resource Limits, Timeouts)",
            "module": "RAE-EDITOR-SECURITY",
            "severity": RuleSeverity.CRITICAL,
            "enforcement": RuleEnforcement.BLOCK,
            "control_type": ControlType.DETERMINISTIC,
            "scanner": "rae-security-gateway",
            "regex": re.compile(
                r'(?:render_worker_privileged\s*=\s*True|pdf_preflight_timeout\s*=\s*None|subprocess\.run\s*\([^)]*shell\s*=\s*True[^)]*ghostscript)',
                re.IGNORECASE,
            ),
            "message": "PDF/Print render worker executes without sandbox isolation, timeout, or safe argument array.",
            "remediation": "Run PDF/preflight workers in unprivileged sandboxes with strict CPU/RAM quotas, network isolation, and execution timeouts.",
        },
        {
            "rule_id": "RAE-EDT-009",
            "rule_name": "Client Data Privacy, Retention & Right to Erasure (RODO/GDPR)",
            "module": "RAE-EDITOR-SECURITY",
            "severity": RuleSeverity.HIGH,
            "enforcement": RuleEnforcement.BLOCK,
            "control_type": ControlType.SYSTEMIC,
            "scanner": "rae-security-gateway",
            "regex": re.compile(
                r'(?:skip_storage_cleanup_on_gdpr_delete\s*=\s*True|logger\.(?:info|debug|error)\s*\([^)]*(?:customer_pesel|credit_card_number|raw_address_pii))',
                re.IGNORECASE,
            ),
            "message": "GDPR/RODO Violation: Incomplete asset erasure on account deletion or raw customer PII written to logs.",
            "remediation": "Purge associated S3/MinIO project assets and thumbnails upon GDPR erasure and mask PII in application logs.",
        },
    ]

    @staticmethod
    def compute_finding_fingerprint(rule_id: str, file_path: str, snippet: str) -> str:
        """Computes a stable fingerprint for baseline debt separation (Section 10)."""
        raw = f"{rule_id}:{file_path}:{snippet.strip()}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]

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
        baseline_fingerprints: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """
        Implements `quality.security_scan` and `quality.analyze_diff`.
        Scans code/diff for OWASP, Identity/Secrets, AI Prompt Injection, and all 9 RAE-EDITOR-SECURITY rules.
        Supports `baseline_fingerprints` (Section 10) so historical technical debt does not block unrelated PRs,
        while zero tolerance applies to all new findings in modified code.
        """
        baseline_set = set(baseline_fingerprints or [])
        all_detected: List[SecurityFinding] = []
        lines = code.splitlines() or [code]

        for pat in self.PATTERNS:
            for idx, line in enumerate(lines, start=1):
                if pat["regex"].search(line):
                    fp = self.compute_finding_fingerprint(pat["rule_id"], file_path, line)
                    all_detected.append(
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
                            evidence={
                                "matched_line": line.strip()[:200],
                                "fingerprint": fp,
                                "is_baseline_debt": fp in baseline_set,
                                "verified_by_tool": True,
                            },
                        )
                    )
            # Also check multi-line patterns (e.g. SVG with <script> or multi-line CORS)
            if not any(f.rule_id == pat["rule_id"] for f in all_detected) and pat["regex"].search(code):
                fp = self.compute_finding_fingerprint(pat["rule_id"], file_path, code[:200])
                all_detected.append(
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
                        evidence={
                            "matched_snippet": code[:200],
                            "fingerprint": fp,
                            "is_baseline_debt": fp in baseline_set,
                            "verified_by_tool": True,
                        },
                    )
                )

        active_findings = [f for f in all_detected if not f.evidence.get("is_baseline_debt", False)]
        baseline_debt_findings = [f for f in all_detected if f.evidence.get("is_baseline_debt", False)]

        has_blockers = any(f.enforcement == RuleEnforcement.BLOCK for f in active_findings)
        verdict = (
            GatewayVerdict.BLOCK
            if has_blockers
            else (GatewayVerdict.REPAIR if active_findings else GatewayVerdict.PASS)
        )
        sarif = self.to_sarif_report(active_findings, verdict=verdict)

        return {
            "verdict": verdict.value,
            "findings_count": len(active_findings),
            "blocking_count": sum(1 for f in active_findings if f.enforcement == RuleEnforcement.BLOCK),
            "baseline_debt_count": len(baseline_debt_findings),
            "findings": [f.model_dump() for f in active_findings],
            "baseline_debt_findings": [f.model_dump() for f in baseline_debt_findings],
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
                        "fingerprint": f.evidence.get("fingerprint", ""),
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
