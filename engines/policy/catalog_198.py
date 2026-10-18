# packages/rae-quality/engines/policy/catalog_198.py
"""
Complete Catalog of 198 Engineering & Security Topics + 12 AI/SaaS Areas + 9 RAE-EDITOR-SECURITY Rules.
Directly implements Sections 1, 2, 3, 4, 5, and 11 of docs/poziom-bezpieczeństwa-kodu.md.
"""

from typing import Dict, List, Tuple
from models.security_v2 import (
    AutofixSpec,
    ControlStage,
    ControlType,
    ModulePriority,
    QualityRule,
    RuleAppliesTo,
    RuleEnforcement,
    RuleSeverity,
    RuleVerification,
)

# Exact 198 topics from docs/poziom-bezpieczeństwa-kodu.md (Lines 3-200)
ALL_198_TOPICS: List[Tuple[int, str]] = [
    (1, "SQL Injection"),
    (2, "XSS"),
    (3, "CSRF"),
    (4, "CORS"),
    (5, "SSRF"),
    (6, "IDOR"),
    (7, "Path Traversal"),
    (8, "Mass Assignment"),
    (9, "Clickjacking"),
    (10, "Content Security Policy"),
    (11, "Security Headers"),
    (12, "Input Validation"),
    (13, "Server-Side Authorization"),
    (14, "Row-Level Security"),
    (15, "Least Privilege"),
    (16, "RBAC"),
    (17, "Secrets Management"),
    (18, ".env in .gitignore"),
    (19, "API Key Rotation"),
    (20, "Secret Scanning"),
    (21, "Hashing vs Encryption"),
    (22, "Password Salting"),
    (23, "bcrypt & Argon2"),
    (24, "JWT Expiry"),
    (25, "Refresh Tokens"),
    (26, "OAuth 2.0"),
    (27, "OpenID Connect"),
    (28, "Session Fixation"),
    (29, "MFA"),
    (30, "Brute Force Protection"),
    (31, "Account Enumeration"),
    (32, "Timing Attacks"),
    (33, "File Upload Validation"),
    (34, "Webhook Signature Verification"),
    (35, "TLS Certificate Expiry"),
    (36, "HSTS"),
    (37, "Encryption at Rest"),
    (38, "Dependency Vulnerabilities"),
    (39, "Supply Chain Attacks"),
    (40, "Threat Modeling"),
    (41, "Indexes"),
    (42, "EXPLAIN ANALYZE"),
    (43, "N+1 Queries"),
    (44, "Full Table Scans"),
    (45, "Connection Pooling"),
    (46, "Database Migrations"),
    (47, "Down Migrations"),
    (48, "Transactions"),
    (49, "ACID"),
    (50, "Isolation Levels"),
    (51, "Deadlocks"),
    (52, "Optimistic Locking"),
    (53, "Pessimistic Locking"),
    (54, "Normalization"),
    (55, "Denormalization"),
    (56, "Foreign Keys"),
    (57, "Unique Constraints"),
    (58, "Cascading Deletes"),
    (59, "Soft Deletes"),
    (60, "UUIDs vs Auto-Increment"),
    (61, "Cursor-Based Pagination"),
    (62, "Full-Text Search"),
    (63, "Read Replicas"),
    (64, "Replication Lag"),
    (65, "Sharding"),
    (66, "Partitioning"),
    (67, "Hot Partitions"),
    (68, "Postgres VACUUM"),
    (69, "Materialized Views"),
    (70, "Backups"),
    (71, "Testing Your Restores"),
    (72, "Point-in-Time Recovery"),
    (73, "Change Data Capture"),
    (74, "Outbox Pattern"),
    (75, "ORM Lazy Loading"),
    (76, "CAP Theorem"),
    (77, "Eventual Consistency"),
    (78, "Strong Consistency"),
    (79, "Raft Consensus"),
    (80, "Leader Election"),
    (81, "Split Brain"),
    (82, "Quorums"),
    (83, "Clock Skew"),
    (84, "Distributed Locks"),
    (85, "Consistent Hashing"),
    (86, "Bloom Filters"),
    (87, "Two-Phase Commit"),
    (88, "CQRS"),
    (89, "Event Sourcing"),
    (90, "Race Conditions"),
    (91, "Backpressure"),
    (92, "Load Shedding"),
    (93, "Bulkheads"),
    (94, "Jitter"),
    (95, "Retry Storms"),
    (96, "Cascading Failures"),
    (97, "Thundering Herd"),
    (98, "Cache Invalidation"),
    (99, "Cache Hit Ratio"),
    (100, "TTLs"),
    (101, "Cache Warming"),
    (102, "Write-Through vs Write-Back"),
    (103, "Redis Eviction Policies"),
    (104, "CDNs"),
    (105, "Cache-Control Headers"),
    (106, "ETags"),
    (107, "Dead Letter Queues"),
    (108, "Poison Messages"),
    (109, "At-Least-Once Delivery"),
    (110, "Exactly-Once Semantics"),
    (111, "Message Ordering"),
    (112, "Kafka Consumer Groups"),
    (113, "Partition Keys"),
    (114, "Background Jobs"),
    (115, "Webhook Retries"),
    (116, "DNS"),
    (117, "DNS Propagation"),
    (118, "HTTP Status Codes"),
    (119, "HTTP Method Semantics"),
    (120, "Keep-Alive"),
    (121, "HTTP/2"),
    (122, "WebSockets"),
    (123, "Server-Sent Events"),
    (124, "Long Polling"),
    (125, "gRPC"),
    (126, "Protocol Buffers"),
    (127, "API Versioning"),
    (128, "OpenAPI Specs"),
    (129, "Backward Compatibility"),
    (130, "Request Size Limits"),
    (131, "Compression"),
    (132, "Latency vs Throughput"),
    (133, "Egress Fees"),
    (134, "VPCs"),
    (135, "Subnets"),
    (136, "NAT Gateways"),
    (137, "Firewalls"),
    (138, "Security Groups"),
    (139, "Service Mesh"),
    (140, "Ingress Controllers"),
    (141, "Health Checks"),
    (142, "Liveness vs Readiness Probes"),
    (143, "Graceful Shutdown"),
    (144, "Connection Draining"),
    (145, "Stateless Services"),
    (146, "Failover"),
    (147, "Multi-Region"),
    (148, "Availability Zones"),
    (149, "Single Points of Failure"),
    (150, "Disaster Recovery"),
    (151, "RTO & RPO"),
    (152, "SLAs"),
    (153, "SLOs"),
    (154, "Error Budgets"),
    (155, "Incident Response"),
    (156, "On-Call"),
    (157, "Runbooks"),
    (158, "Postmortems"),
    (159, "Chaos Engineering"),
    (160, "Graceful Degradation"),
    (161, "Autoscaling"),
    (162, "Horizontal vs Vertical Scaling"),
    (163, "Cold Starts"),
    (164, "Capacity Planning"),
    (165, "Load Testing"),
    (166, "Memory Leaks"),
    (167, "OOM Killer"),
    (168, "Structured Logging"),
    (169, "Log Levels"),
    (170, "Log Rotation"),
    (171, "Distributed Tracing"),
    (172, "OpenTelemetry"),
    (173, "Correlation IDs"),
    (174, "Metrics Cardinality"),
    (175, "p99 Latency"),
    (176, "Alert Fatigue"),
    (177, "Error Tracking"),
    (178, "Profiling"),
    (179, "Flame Graphs"),
    (180, "Infrastructure as Code"),
    (181, "Terraform State"),
    (182, "GitOps"),
    (183, "Blue-Green Deployments"),
    (184, "Canary Releases"),
    (185, "Rollbacks"),
    (186, "Feature Flags"),
    (187, "Environment Parity"),
    (188, "Staging Environments"),
    (189, "12-Factor Apps"),
    (190, "Multi-Stage Builds"),
    (191, "Non-Root Containers"),
    (192, "Image Scanning"),
    (193, "Resource Requests & Limits"),
    (194, "Pod Disruption Budgets"),
    (195, "Semantic Versioning"),
    (196, "Lockfiles"),
    (197, "Reproducible Builds"),
    (198, "Branch Protection"),
]

# Section 11: 12 Additional AI & Multi-Tenant SaaS Security Topics (199-210)
ADDITIONAL_AI_SAAS_TOPICS: List[Tuple[int, str, str]] = [
    (199, "AI Prompt Injection", "Złośliwe instrukcje w repozytorium, dokumentach i danych wejściowych"),
    (200, "Agent Tool Permissions", "Ograniczenie uprawnień agentów do narzędzi, repozytoriów i produkcji"),
    (201, "Tenant Isolation Testing", "Automatyczne próby przekraczania granic klientów SaaS"),
    (202, "Business Logic Security", "Manipulacja cenami, zamówieniami, rabatami i uprawnieniami"),
    (203, "SBOM & Provenance", "Identyfikowalność zależności i pochodzenia artefaktów"),
    (204, "Artifact Signing", "Potwierdzenie, że wdrażany jest dokładnie zatwierdzony artefakt"),
    (205, "Security Regression Tests", "Każda naprawiona podatność pozostawia trwały test"),
    (206, "Data Privacy & Retention", "Ochrona danych osobowych, zdjęć, EXIF i zasad retencji"),
    (207, "Safe Deserialization", "Ochrona przed niebezpiecznym odtwarzaniem obiektów"),
    (208, "Agent Self-Modification Protection", "Agent nie może osłabiać własnych reguł kontroli"),
    (209, "Resource Exhaustion", "Limity CPU, RAM, rozmiaru projektów i kosztów AI"),
    (210, "Audit Trail Integrity", "Niezmienialna historia decyzji i zatwierdzeń bezpieczeństwa"),
]

# Section 2: 12 Control Modules mapping
MODULE_DEFINITIONS: List[Dict[str, object]] = [
    {
        "id": "security_owasp",
        "name": "Security & OWASP",
        "ranges": [(1, 16), (33, 40)],
        "priority": ModulePriority.P0,
        "default_scanner": "semgrep+codeql+trivy",
    },
    {
        "id": "identity_secrets",
        "name": "Identity & Secrets",
        "ranges": [(17, 32)],
        "priority": ModulePriority.P0,
        "default_scanner": "gitleaks+semgrep",
    },
    {
        "id": "database_integrity",
        "name": "Database Integrity",
        "ranges": [(41, 75)],
        "priority": ModulePriority.P1,
        "default_scanner": "rae-architecture-engine",
    },
    {
        "id": "distributed_systems",
        "name": "Distributed Systems",
        "ranges": [(76, 97)],
        "priority": ModulePriority.P2,
        "default_scanner": "rae-architecture-engine+k6",
    },
    {
        "id": "cache_performance",
        "name": "Cache & Performance",
        "ranges": [(98, 106)],
        "priority": ModulePriority.P2,
        "default_scanner": "rae-architecture-engine",
    },
    {
        "id": "messaging_jobs",
        "name": "Messaging & Jobs",
        "ranges": [(107, 115)],
        "priority": ModulePriority.P1_P2,
        "default_scanner": "rae-architecture-engine",
    },
    {
        "id": "network_api",
        "name": "Network & API",
        "ranges": [(116, 133)],
        "priority": ModulePriority.P1,
        "default_scanner": "schemathesis+owasp-zap",
    },
    {
        "id": "infrastructure_security",
        "name": "Infrastructure Security",
        "ranges": [(134, 150)],
        "priority": ModulePriority.P1,
        "default_scanner": "checkov+trivy",
    },
    {
        "id": "reliability_operations",
        "name": "Reliability & Operations",
        "ranges": [(151, 167)],
        "priority": ModulePriority.P1_P2,
        "default_scanner": "k6+rae-infra-engine",
    },
    {
        "id": "observability",
        "name": "Observability",
        "ranges": [(168, 179)],
        "priority": ModulePriority.P1,
        "default_scanner": "rae-infra-engine",
    },
    {
        "id": "delivery_containers",
        "name": "Delivery & Containers",
        "ranges": [(180, 194)],
        "priority": ModulePriority.P0_P1,
        "default_scanner": "trivy+checkov",
    },
    {
        "id": "supply_chain_git",
        "name": "Supply Chain & Git",
        "ranges": [(195, 198)],
        "priority": ModulePriority.P0,
        "default_scanner": "trivy+rae-git-guard",
    },
]

# Section 4: RAE-EDITOR-SECURITY Custom Rule Suite (9 rules)
RAE_EDITOR_SECURITY_RULES: List[QualityRule] = [
    QualityRule(
        id="RAE-EDT-001",
        version="1.0.0",
        name="Project, Page, Asset and Order Level Authorization",
        category="editor_authorization",
        module="RAE-EDITOR-SECURITY",
        priority=ModulePriority.P0,
        severity=RuleSeverity.CRITICAL,
        enforcement=RuleEnforcement.BLOCK,
        control_type=ControlType.AI_SEMANTIC,
        stage=ControlStage.PRE_MERGE,
        applies_to=RuleAppliesTo(
            languages=["typescript", "javascript", "php", "python"],
            components=["editor", "api", "backend"],
        ),
        triggers=["editor_resource_access", "order_mutation", "page_mutation", "asset_access"],
        verification=RuleVerification(static_analysis=True, ai_review=True, integration_test=True, negative_test=True),
        requirements=[
            "Verify ownership at project, page, asset, and order granularity",
            "Deny cross-project asset injection or page cloning without ownership proof",
        ],
        evidence_required=["source_location", "affected_endpoint", "authorization_path", "test_result"],
        scanner="semgrep+playwright",
    ),
    QualityRule(
        id="RAE-EDT-002",
        version="1.0.0",
        name="Multi-Printshop Data Isolation (Cache, WebSockets, Queues, Files)",
        category="tenant_isolation",
        module="RAE-EDITOR-SECURITY",
        priority=ModulePriority.P0,
        severity=RuleSeverity.CRITICAL,
        enforcement=RuleEnforcement.BLOCK,
        control_type=ControlType.DETERMINISTIC,
        stage=ControlStage.PRE_MERGE,
        applies_to=RuleAppliesTo(
            languages=["typescript", "javascript", "php", "python"],
            components=["editor", "api", "backend", "cache", "websocket", "queue"],
        ),
        triggers=["cache_key_defined", "websocket_room_joined", "queue_job_dispatched", "storage_path_resolved"],
        verification=RuleVerification(static_analysis=True, ai_review=True, integration_test=True, negative_test=True),
        requirements=[
            "Prefix all Redis cache keys, WebSocket rooms, queue payloads, and S3/local file paths with tenant_id",
            "Block cross-printshop event broadcasting or shared cache poisoning",
        ],
        evidence_required=["source_location", "authorization_path", "test_result"],
        scanner="semgrep+rae-security-gateway",
    ),
    QualityRule(
        id="RAE-EDT-003",
        version="1.0.0",
        name="Printshop Admin Project Access & Impersonation Audit",
        category="authorization",
        module="RAE-EDITOR-SECURITY",
        priority=ModulePriority.P0,
        severity=RuleSeverity.HIGH,
        enforcement=RuleEnforcement.BLOCK,
        control_type=ControlType.AI_SEMANTIC,
        stage=ControlStage.PRE_MERGE,
        applies_to=RuleAppliesTo(
            languages=["typescript", "javascript", "php", "python"],
            components=["editor", "backend", "api"],
        ),
        triggers=["admin_impersonation", "project_support_access"],
        verification=RuleVerification(static_analysis=True, ai_review=True, integration_test=True),
        requirements=[
            "Printshop admin may only access projects belonging to their own printshop tenant",
            "Emit immutable audit log entry whenever admin opens or edits a customer project",
        ],
        evidence_required=["source_location", "authorization_path", "test_result"],
        scanner="rae-security-gateway",
    ),
    QualityRule(
        id="RAE-EDT-004",
        version="1.0.0",
        name="Multi-User Collaborative Project Editing Safety",
        category="concurrency",
        module="RAE-EDITOR-SECURITY",
        priority=ModulePriority.P1,
        severity=RuleSeverity.HIGH,
        enforcement=RuleEnforcement.REPAIR,
        control_type=ControlType.DETERMINISTIC,
        stage=ControlStage.PRE_MERGE,
        applies_to=RuleAppliesTo(
            languages=["typescript", "javascript", "python"],
            components=["editor", "websocket", "api"],
        ),
        triggers=["collaborative_sync_changed", "scene_save_changed"],
        verification=RuleVerification(static_analysis=True, integration_test=True, negative_test=True),
        requirements=[
            "Prevent lost updates during simultaneous saves via optimistic locking (version/ETag) or CRDT/Yjs conflict resolution",
            "Enforce per-collaborator role permissions (viewer vs editor)",
        ],
        evidence_required=["source_location", "test_result"],
        scanner="playwright+k6",
    ),
    QualityRule(
        id="RAE-EDT-005",
        version="1.0.0",
        name="Production Parameter Server-Side Validation (Format, Bleed, Pages, Price)",
        category="business_logic",
        module="RAE-EDITOR-SECURITY",
        priority=ModulePriority.P0,
        severity=RuleSeverity.CRITICAL,
        enforcement=RuleEnforcement.BLOCK,
        control_type=ControlType.DETERMINISTIC,
        stage=ControlStage.PRE_MERGE,
        applies_to=RuleAppliesTo(
            languages=["php", "typescript", "javascript", "python"],
            components=["editor", "backend", "api", "calculator"],
        ),
        triggers=["pricing_logic_changed", "order_checkout_changed", "dtp_spec_changed"],
        verification=RuleVerification(static_analysis=True, ai_review=True, integration_test=True, negative_test=True),
        requirements=[
            "Never trust client-submitted price, discount, page count, bleed, or format dimensions",
            "Recalculate price and validate DTP geometry server-side before order acceptance",
        ],
        evidence_required=["source_location", "affected_endpoint", "test_result"],
        scanner="rae-security-gateway+schemathesis",
    ),
    QualityRule(
        id="RAE-EDT-006",
        version="1.0.0",
        name="Production PDF File Tampering & Replacement Protection",
        category="file_integrity",
        module="RAE-EDITOR-SECURITY",
        priority=ModulePriority.P0,
        severity=RuleSeverity.CRITICAL,
        enforcement=RuleEnforcement.BLOCK,
        control_type=ControlType.DETERMINISTIC,
        stage=ControlStage.PRE_MERGE,
        applies_to=RuleAppliesTo(
            languages=["php", "typescript", "javascript", "python"],
            components=["editor", "backend", "api", "storage"],
        ),
        triggers=["pdf_export_changed", "production_file_upload"],
        verification=RuleVerification(static_analysis=True, integration_test=True, negative_test=True),
        requirements=[
            "Protect approved production PDFs with cryptographic SHA-256 checksums and signed URLs",
            "Block unauthorized overwrite of print-ready PDF after order lock",
        ],
        evidence_required=["source_location", "test_result"],
        scanner="rae-security-gateway",
    ),
    QualityRule(
        id="RAE-EDT-007",
        version="1.0.0",
        name="Safe Image Processing & EXIF Geolocation Metadata Sanitization",
        category="privacy_upload",
        module="RAE-EDITOR-SECURITY",
        priority=ModulePriority.P1,
        severity=RuleSeverity.HIGH,
        enforcement=RuleEnforcement.BLOCK,
        control_type=ControlType.DETERMINISTIC,
        stage=ControlStage.PRE_MERGE,
        applies_to=RuleAppliesTo(
            languages=["php", "typescript", "javascript", "python"],
            components=["editor", "backend", "api"],
        ),
        triggers=["image_upload_changed", "asset_pipeline_changed"],
        verification=RuleVerification(static_analysis=True, integration_test=True, negative_test=True),
        requirements=[
            "Strip sensitive EXIF metadata (GPS coordinates, camera serials) while preserving ICC color profiles for DTP",
            "Sanitize SVG uploads against embedded <script>, onload, and XXE payloads",
        ],
        evidence_required=["source_location", "test_result"],
        scanner="semgrep+rae-security-gateway",
    ),
    QualityRule(
        id="RAE-EDT-008",
        version="1.0.0",
        name="AI Model Cost Quota & Invocation Permission Control",
        category="ai_governance",
        module="RAE-EDITOR-SECURITY",
        priority=ModulePriority.P0,
        severity=RuleSeverity.HIGH,
        enforcement=RuleEnforcement.BLOCK,
        control_type=ControlType.DETERMINISTIC,
        stage=ControlStage.PRE_MERGE,
        applies_to=RuleAppliesTo(
            languages=["python", "typescript", "javascript", "php"],
            components=["editor", "api", "backend", "ai"],
        ),
        triggers=["llm_call_added", "ai_image_generation_changed"],
        verification=RuleVerification(static_analysis=True, integration_test=True),
        requirements=[
            "Enforce per-tenant token/cost budgets and rate limits on all AI/LLM endpoints",
            "Verify user role authorization before invoking paid external AI models",
        ],
        evidence_required=["source_location", "test_result"],
        scanner="rae-security-gateway",
    ),
    QualityRule(
        id="RAE-EDT-009",
        version="1.0.0",
        name="Prompt Injection Protection in Documents, Images, Descriptions and External Sources",
        category="ai_security",
        module="RAE-EDITOR-SECURITY",
        priority=ModulePriority.P0,
        severity=RuleSeverity.CRITICAL,
        enforcement=RuleEnforcement.BLOCK,
        control_type=ControlType.AI_SEMANTIC,
        stage=ControlStage.PRE_MERGE,
        applies_to=RuleAppliesTo(
            languages=["python", "typescript", "javascript", "php"],
            components=["editor", "api", "backend", "ai"],
        ),
        triggers=["prompt_template_changed", "external_data_ingestion_changed", "document_ocr_changed"],
        verification=RuleVerification(static_analysis=True, ai_review=True, negative_test=True),
        requirements=[
            "Isolate untrusted document text, OCR output, image metadata, and external URLs from system instructions",
            "Scan ingested content for indirect prompt injection and tool-hijacking payloads",
        ],
        evidence_required=["source_location", "test_result"],
        scanner="rae-security-gateway",
    ),
]


def _resolve_module_for_topic(topic_num: int) -> Dict[str, object]:
    for mod in MODULE_DEFINITIONS:
        for start, end in mod["ranges"]:  # type: ignore[index]
            if start <= topic_num <= end:
                return mod
    return {
        "id": "agentic_ai_security",
        "name": "Agentic AI & SaaS Governance",
        "priority": ModulePriority.P0,
        "default_scanner": "rae-security-gateway",
    }


def _determine_control_type(topic_num: int) -> ControlType:
    # Deterministic: secrets, SAST, dependencies, containers, lockfiles, headers
    deterministic_ranges = list(range(1, 13)) + list(range(17, 25)) + [33, 36, 38, 39] + list(range(190, 199)) + [203, 204, 207, 208, 210]
    # Systemic: backups, restores, PITR, failover, multi-region, RTO/RPO, chaos, TLS cert expiry, K8s cluster
    systemic_nums = {35, 63, 64, 70, 71, 72, 134, 135, 136, 137, 138, 146, 147, 148, 150, 151, 152, 153, 154, 155, 156, 157, 158, 159}
    if topic_num in systemic_nums:
        return ControlType.SYSTEMIC
    if topic_num in deterministic_ranges:
        return ControlType.DETERMINISTIC
    return ControlType.AI_SEMANTIC


def _determine_technologies(topic_num: int, name: str) -> List[str]:
    lower = name.lower()
    if "postgres" in lower:
        return ["postgresql"]
    if "kafka" in lower:
        return ["kafka"]
    if "redis" in lower:
        return ["redis"]
    if "graphql" in lower or "grpc" in lower or "protocol buffers" in lower:
        return ["grpc", "protobuf"]
    if "terraform" in lower:
        return ["terraform"]
    if "pod disruption" in lower or "liveness vs readiness" in lower or "ingress" in lower:
        return ["kubernetes"]
    return []


def build_full_rule_catalog() -> Dict[str, QualityRule]:
    """
    Builds the complete versioned dictionary of 219 rules:
    - RAE-SEC-001 .. RAE-SEC-198 (the 198 catalog topics)
    - RAE-SEC-199 .. RAE-SEC-210 (the 12 AI/SaaS extensions)
    - RAE-EDT-001 .. RAE-EDT-009 (the 9 RAE-EDITOR-SECURITY rules)
    """
    catalog: Dict[str, QualityRule] = {}

    for topic_num, topic_name in ALL_198_TOPICS:
        rule_id = f"RAE-SEC-{topic_num:03d}"
        mod = _resolve_module_for_topic(topic_num)
        priority: ModulePriority = mod["priority"]  # type: ignore[assignment]
        c_type = _determine_control_type(topic_num)
        techs = _determine_technologies(topic_num, topic_name)

        # Canonical Section 5 override for RAE-SEC-006 (IDOR / Cross-tenant object access)
        if topic_num == 6:
            catalog[rule_id] = QualityRule(
                id="RAE-SEC-006",
                version="1.0.0",
                topic_number=6,
                name="Cross-tenant object access (IDOR)",
                category="authorization",
                module=str(mod["name"]),
                priority=ModulePriority.P0,
                severity=RuleSeverity.CRITICAL,
                enforcement=RuleEnforcement.BLOCK,
                control_type=ControlType.AI_SEMANTIC,
                stage=ControlStage.PRE_MERGE,
                applies_to=RuleAppliesTo(
                    languages=["php", "typescript", "javascript", "python"],
                    components=["api", "backend"],
                    technologies=[],
                ),
                triggers=[
                    "resource_access_changed",
                    "authorization_logic_changed",
                    "tenant_context_changed",
                ],
                verification=RuleVerification(
                    static_analysis=True,
                    ai_review=True,
                    integration_test=True,
                    negative_test=True,
                ),
                requirements=[
                    "Server must resolve authenticated identity",
                    "Resource must belong to authorized tenant",
                    "Client-provided tenant ID is untrusted",
                    "Access must be denied across tenants",
                ],
                evidence_required=[
                    "source_location",
                    "affected_endpoint",
                    "authorization_path",
                    "test_result",
                ],
                autofix=AutofixSpec(enabled=True, require_revalidation=True, max_attempts=3),
                scanner="semgrep+rae-security-gateway+playwright",
            )
            continue

        is_p0 = priority == ModulePriority.P0 or topic_num in {1, 2, 5, 6, 7, 8, 13, 14, 17, 18, 20, 33, 38, 191, 195, 198}
        severity = RuleSeverity.CRITICAL if is_p0 else (RuleSeverity.HIGH if "P1" in priority.value else RuleSeverity.MEDIUM)
        enforcement = RuleEnforcement.BLOCK if is_p0 else RuleEnforcement.REPAIR
        stage = ControlStage.PRE_PROD_POST_DEPLOY if c_type == ControlType.SYSTEMIC else ControlStage.PRE_MERGE

        catalog[rule_id] = QualityRule(
            id=rule_id,
            version="1.0.0",
            topic_number=topic_num,
            name=topic_name,
            category=str(mod["id"]),
            module=str(mod["name"]),
            priority=priority,
            severity=severity,
            enforcement=enforcement,
            control_type=c_type,
            stage=stage,
            applies_to=RuleAppliesTo(
                languages=["python", "php", "typescript", "javascript"],
                components=["api", "backend", "frontend", "editor", "infra"],
                technologies=techs,
            ),
            triggers=[f"{mod['id']}_changed"],
            verification=RuleVerification(
                static_analysis=(c_type == ControlType.DETERMINISTIC),
                ai_review=(c_type == ControlType.AI_SEMANTIC),
                integration_test=is_p0,
                negative_test=(topic_num in {1, 2, 5, 6, 7, 8, 13, 14, 33, 48, 90}),
                systemic_check=(c_type == ControlType.SYSTEMIC),
            ),
            requirements=[f"Enforce {topic_name} compliance in {mod['name']}"],
            evidence_required=["source_location", "test_result"] if is_p0 else ["scanner_output"],
            autofix=AutofixSpec(enabled=True, require_revalidation=True, max_attempts=3),
            scanner=str(mod["default_scanner"]),
        )

    # Add 12 AI & SaaS Topics (199-210)
    for topic_num, topic_name, description in ADDITIONAL_AI_SAAS_TOPICS:
        rule_id = f"RAE-SEC-{topic_num:03d}"
        c_type = _determine_control_type(topic_num)
        catalog[rule_id] = QualityRule(
            id=rule_id,
            version="1.0.0",
            topic_number=topic_num,
            name=topic_name,
            category="agentic_ai_security",
            module="Agentic AI & SaaS Governance",
            priority=ModulePriority.P0,
            severity=RuleSeverity.CRITICAL,
            enforcement=RuleEnforcement.BLOCK,
            control_type=c_type,
            stage=ControlStage.PRE_MERGE,
            applies_to=RuleAppliesTo(
                languages=["python", "php", "typescript", "javascript"],
                components=["api", "backend", "editor", "agent", "infra"],
                technologies=[],
            ),
            triggers=["agent_code_change", "security_policy_touch", "tenant_boundary_touch"],
            verification=RuleVerification(
                static_analysis=True,
                ai_review=True,
                integration_test=True,
                negative_test=True,
            ),
            requirements=[description],
            evidence_required=["source_location", "test_result", "scanner_output"],
            autofix=AutofixSpec(enabled=(topic_num != 208), require_revalidation=True, max_attempts=3),
            scanner="rae-security-gateway",
        )

    # Add 9 RAE-EDITOR-SECURITY rules
    for edt_rule in RAE_EDITOR_SECURITY_RULES:
        catalog[edt_rule.id] = edt_rule

    return catalog
