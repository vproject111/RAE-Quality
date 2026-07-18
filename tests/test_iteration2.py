# RAE-Quality/tests/test_iteration2.py
import pytest
from unittest.mock import AsyncMock, patch, MagicMock, mock_open
from engines.security.gitleaks import GitleaksEngine
from engines.security.trivy import TrivyEngine
from models.report import Verdict, Severity
from core.policy import load_quality_policy
import os
import json

@pytest.mark.asyncio
async def test_gitleaks_engine_detects_leaks():
    """GitleaksEngine should successfully parse leaks report and set verdict to REJECTED."""
    # Mocking subprocess run and report file creation
    mock_process = AsyncMock()
    mock_process.returncode = 1
    mock_process.communicate.return_value = (b"", b"")
    
    gitleaks_output = [
        {
            "Description": "AWS API Key",
            "StartLine": 12,
            "File": "config.py",
            "RuleID": "aws-api-key"
        }
    ]
    
    with patch("asyncio.create_subprocess_exec", return_value=mock_process), \
         patch("os.path.exists", lambda path: True if "gitleaks_report.json" in path else False), \
         patch("builtins.open", mock_open(read_data=json.dumps(gitleaks_output))):
         
        engine = GitleaksEngine(project_path="/tmp/test-project")
        report = await engine.run()
        
        assert report.verdict == Verdict.REJECTED
        assert report.score == 0.0
        assert len(report.issues) == 1
        assert report.issues[0].severity == Severity.CRITICAL
        assert "UNIEWAŻNIJ KLUCZ" in report.issues[0].fix_suggestion

@pytest.mark.asyncio
async def test_trivy_engine_detects_vulnerabilities():
    """TrivyEngine should parse vulnerabilities and calculate appropriate score."""
    mock_process = AsyncMock()
    mock_process.returncode = 0
    mock_process.communicate.return_value = (b"", b"")
    
    trivy_output = {
        "Results": [
            {
                "Target": "requirements.txt",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2023-38325",
                        "PkgName": "cryptography",
                        "InstalledVersion": "41.0.1",
                        "FixedVersion": "41.0.2",
                        "Severity": "HIGH",
                        "Title": "Regular Expression Denial of Service"
                    }
                ],
                "Misconfigurations": [
                    {
                        "ID": "AVD-KSV-0001",
                        "Title": "Container running as root",
                        "Severity": "MEDIUM",
                        "Message": "Root user detected",
                        "Resolution": "Use non-root user"
                    }
                ]
            }
        ]
    }
    
    with patch("asyncio.create_subprocess_exec", return_value=mock_process), \
         patch("os.path.exists", lambda path: True if "trivy_report.json" in path else False), \
         patch("builtins.open", mock_open(read_data=json.dumps(trivy_output))):
         
        engine = TrivyEngine(project_path="/tmp/test-project")
        report = await engine.run()
        
        # High/medium issues penalty: 1.0 - 0.1 (high) - 2 * 0.02 = 0.86
        assert report.score == 0.86
        assert len(report.issues) == 2
        assert report.issues[0].severity == Severity.HIGH
        assert report.issues[1].severity == Severity.MEDIUM

def test_quality_policy_loading():
    """Policy loading should parse policy from YAML and set defaults if missing."""
    policy_data = """
    quality_gate:
      min_coverage: 0.82
      min_type_safety: 0.88
      max_complexity: 12.0
      min_score: 0.75
    """
    with patch("os.path.exists", return_value=True), \
         patch("builtins.open", mock_open(read_data=policy_data)):
        policy = load_quality_policy("quality_policy.yaml")
        assert policy.min_coverage == 0.82
        assert policy.min_type_safety == 0.88
        assert policy.max_complexity == 12.0
        assert policy.min_score == 0.75

@pytest.mark.asyncio
async def test_sonarqube_webhook_verification(mock_rae_api):
    """SonarQube webhook should verify signature and trigger actions on failure."""
    from main import app
    from fastapi.testclient import TestClient
    import hmac
    import hashlib
    
    client = TestClient(app)
    
    payload = {
        "project": {"key": "test-project", "url": "http://sonar/test-project"},
        "qualityGate": {"status": "ERROR"}
    }
    body = json.dumps(payload).encode()
    
    secret = "sonarqube_webhook_secret_key"
    signature = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    
    # We must patch _save_audit_result_to_memory and _enforce_verdict to avoid network calls
    with patch("main.sentinel._save_audit_result_to_memory") as mock_save, \
         patch("main.sentinel._enforce_verdict") as mock_enforce:
         
        # Test valid signature, status ERROR
        response = client.post(
            "/v2/quality/webhook/sonarqube",
            content=body,
            headers={"X-Sonar-Webhook-HMAC-Signature": signature}
        )
        assert response.status_code == 200
        assert mock_save.called
        assert mock_enforce.called
        
        # Test invalid signature
        response = client.post(
            "/v2/quality/webhook/sonarqube",
            content=body,
            headers={"X-Sonar-Webhook-HMAC-Signature": "invalid-sig"}
        )
        assert response.status_code == 401
