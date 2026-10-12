# packages/rae-quality/engines/security/sonar_client.py
import os
from typing import Any, Dict, List, Optional
import httpx

class SonarQubeClient:
    """
    Client for interacting with local/cluster SonarQube API.
    Retrieves system health, Quality Gate status, and critical security issues.
    """

    DEFAULT_TOKEN = "squ_1111222233334444555566667777888899990000"
    DEFAULT_PROJECTS = ["editornext", "backend", "next-frontend", "next-manager"]

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

    def get_aggregate_security_score(self, projects: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Aggregates Quality Gate status across all core projects.
        Returns a verification score from 0.0 to 1.0.
        """
        target_projects = projects or self.DEFAULT_PROJECTS
        results = []
        all_ok = True
        failed_projects = []

        for p in target_projects:
            qg = self.get_project_quality_gate(p)
            results.append(qg)
            if not qg.get("is_ok", False):
                all_ok = False
                failed_projects.append(p)

        passed_count = sum(1 for r in results if r.get("is_ok", False))
        total_count = len(results)
        score = (passed_count / total_count) if total_count > 0 else 0.0

        return {
            "all_gates_passed": all_ok,
            "verification_score": round(score, 2),
            "passed_count": passed_count,
            "total_count": total_count,
            "failed_projects": failed_projects,
            "details": results
        }
