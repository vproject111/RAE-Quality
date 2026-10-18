# packages/rae-quality/engines/security/sonar_client.py
import os
from typing import Any, Dict, List, Optional
import httpx

class SonarQubeClient:
    """
    Client for interacting with local/cluster SonarQube API.
    Retrieves system health, Quality Gate status, and enforces strict SonarQube Rating A criteria:
    - Vulnerabilities == 0 (Rating A)
    - Bugs == 0 (Rating A)
    - Code Smells == 0 (Rating A)
    - Security Hotspots Reviewed == 100% (0 open hotspots)
    - Line/Branch Coverage >= 90.0%
    - Duplicated Lines Density == 0.0%
    """

    DEFAULT_TOKEN = "squ_1111222233334444555566667777888899990000"
    DEFAULT_PROJECTS = ["editornext", "backend", "next-frontend", "next-manager"]

    # Strict Rating A thresholds as specified in dreamsoft_factory/docs/testy-sonarqube.txt
    REQUIRED_METRICS = {
        "vulnerabilities": 0,
        "bugs": 0,
        "code_smells": 0,
        "security_hotspots": 0,
        "min_coverage": 90.0,
        "max_duplications": 0.0
    }

    def __init__(self, base_url: Optional[str] = None, token: Optional[str] = None):
        # Auto-detect whether running inside Docker container or on host
        if not base_url:
            base_url = os.environ.get("SONARQUBE_API_URL")
            if not base_url:
                # Inside docker network use service name, on host use localhost
                base_url = "http://sonarqube:9000" if os.path.exists("/.dockerenv") else "http://localhost:9000"
        
        self.base_url = base_url.rstrip("/")
        self.token = token or os.environ.get("SONARQUBE_API_TOKEN", self.DEFAULT_TOKEN)

    def _get_auth(self):
        return (self.token, "")

    def get_system_status(self) -> Dict[str, Any]:
        """Queries /api/system/status."""
        try:
            with httpx.Client(timeout=4.0) as client:
                resp = client.get(f"{self.base_url}/api/system/status")
                if resp.status_code == 200:
                    return resp.json()
        except Exception as e:
            return {"status": "DOWN", "error": str(e)}
        return {"status": "DOWN", "error": "Unexpected HTTP status"}

    def get_project_quality_gate(self, project_key: str) -> Dict[str, Any]:
        """Queries /api/qualitygates/project_status?projectKey={project_key}."""
        try:
            with httpx.Client(timeout=4.0, auth=self._get_auth()) as client:
                resp = client.get(f"{self.base_url}/api/qualitygates/project_status", params={"projectKey": project_key})
                if resp.status_code == 200:
                    data = resp.json().get("projectStatus", {})
                    return {
                        "project": project_key,
                        "status": data.get("status", "UNKNOWN"),
                        "conditions": data.get("conditions", []),
                        "is_ok": data.get("status") == "OK"
                    }
        except Exception as e:
            return {"project": project_key, "status": "ERROR", "error": str(e), "is_ok": False}
        return {"project": project_key, "status": "UNKNOWN", "is_ok": False}

    def get_strict_project_measures(self, project_key: str) -> Dict[str, Any]:
        """
        Queries /api/measures/component to inspect the 6 strict Rating A criteria:
        vulnerabilities, bugs, code_smells, security_hotspots, coverage, duplicated_lines_density.
        """
        metric_keys = "vulnerabilities,bugs,code_smells,security_hotspots,coverage,duplicated_lines_density"
        try:
            with httpx.Client(timeout=4.0, auth=self._get_auth()) as client:
                resp = client.get(
                    f"{self.base_url}/api/measures/component",
                    params={"component": project_key, "metricKeys": metric_keys}
                )
                if resp.status_code == 200:
                    raw_measures = resp.json().get("component", {}).get("measures", [])
                    m_map = {m["metric"]: m.get("value", "0") for m in raw_measures}
                    
                    vulns = int(m_map.get("vulnerabilities", 0))
                    bugs = int(m_map.get("bugs", 0))
                    smells = int(m_map.get("code_smells", 0))
                    hotspots = int(m_map.get("security_hotspots", 0))
                    coverage = float(m_map.get("coverage", 0.0))
                    duplications = float(m_map.get("duplicated_lines_density", 0.0))

                    violations = []
                    if vulns > self.REQUIRED_METRICS["vulnerabilities"]:
                        violations.append(f"Vulnerabilities: {vulns} (Required: 0)")
                    if bugs > self.REQUIRED_METRICS["bugs"]:
                        violations.append(f"Bugs: {bugs} (Required: 0)")
                    if smells > self.REQUIRED_METRICS["code_smells"]:
                        violations.append(f"Code Smells: {smells} (Required: 0)")
                    if hotspots > self.REQUIRED_METRICS["security_hotspots"]:
                        violations.append(f"Security Hotspots Unreviewed: {hotspots} (Required: 0)")
                    if coverage < self.REQUIRED_METRICS["min_coverage"]:
                        violations.append(f"Coverage: {coverage:.1f}% (Required: >90.0%)")
                    if duplications > self.REQUIRED_METRICS["max_duplications"]:
                        violations.append(f"Duplicated Lines: {duplications:.1f}% (Required: 0.0%)")

                    is_strict_a = len(violations) == 0
                    return {
                        "project": project_key,
                        "is_strict_a": is_strict_a,
                        "vulnerabilities": vulns,
                        "bugs": bugs,
                        "code_smells": smells,
                        "security_hotspots": hotspots,
                        "coverage": coverage,
                        "duplicated_lines_density": duplications,
                        "violations": violations
                    }
        except Exception as e:
            return {
                "project": project_key,
                "is_strict_a": False,
                "error": str(e),
                "violations": [f"Connection error: {str(e)}"]
            }
        return {
            "project": project_key,
            "is_strict_a": False,
            "error": "Unexpected HTTP status",
            "violations": ["Could not retrieve measures from SonarQube"]
        }

    def get_aggregate_security_score(self, projects: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Aggregates Quality Gate status AND strict SonarQube Rating A measures across all core projects.
        Returns a verification score from 0.0 to 1.0.
        """
        target_projects = projects or self.DEFAULT_PROJECTS
        gate_results = []
        strict_results = []
        all_ok = True
        all_strict_a = True
        failed_projects = []

        for p in target_projects:
            qg = self.get_project_quality_gate(p)
            gate_results.append(qg)
            
            strict = self.get_strict_project_measures(p)
            strict_results.append(strict)

            project_passed = qg.get("is_ok", False) and strict.get("is_strict_a", False)
            if not project_passed:
                all_ok = False
                all_strict_a = False
                failed_projects.append(p)

        passed_count = sum(1 for p in target_projects if p not in failed_projects)
        total_count = len(target_projects)
        score = (passed_count / total_count) if total_count > 0 else 0.0

        return {
            "all_gates_passed": all_ok,
            "all_strict_a_passed": all_strict_a,
            "verification_score": round(score, 2),
            "passed_count": passed_count,
            "total_count": total_count,
            "failed_projects": failed_projects,
            "gate_details": gate_results,
            "strict_measures": strict_results,
            "details": gate_results  # Backward compatibility
        }
