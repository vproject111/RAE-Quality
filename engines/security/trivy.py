# engines/security/trivy.py
import asyncio
import json
import os
from core.base_engine import BaseQualityEngine
from models.report import ScanReport, QualityIssue, Severity, Verdict

class TrivyEngine(BaseQualityEngine):
    """Silnik skanowania podatności bibliotek, obrazów i IaC za pomocą Trivy."""
    
    async def run(self) -> ScanReport:
        self.logger.info("Starting Trivy FS Scan...")
        report_file = "trivy_report.json"
        
        # Cleanup old report
        if os.path.exists(report_file):
            try:
                os.remove(report_file)
            except:
                pass

        try:
            # Uruchomienie Trivy w trybie filesystem (fs) z opcjonalnym lokalnym proxy bazy luk
            cmd = ["trivy", "fs", "--format", "json", "--output", report_file]
            
            db_repo = os.getenv("TRIVY_DB_REPOSITORY")
            if db_repo:
                cmd.extend(["--db-repository", db_repo])
            else:
                local_registry = os.getenv("LOCAL_OCI_REGISTRY")
                if local_registry:
                    cmd.extend(["--db-repository", f"{local_registry}/trivy-db"])
                    
            cmd.append(self.project_path)
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()
            exit_code = process.returncode
            self.logger.info(f"Trivy exited with code {exit_code}")
            
            issues = []
            vulns_count = 0
            misconfigs_count = 0
            
            if os.path.exists(report_file):
                try:
                    with open(report_file, "r") as f:
                        data = json.load(f) or {}
                        results = data.get("Results", [])
                        for result in results:
                            target = result.get("Target", "unknown")
                            
                            # 1. Przetwarzanie podatności (Vulnerabilities)
                            for vuln in result.get("Vulnerabilities", []):
                                vulns_count += 1
                                issues.append(QualityIssue(
                                    id=vuln.get("VulnerabilityID"),
                                    engine="Trivy",
                                    severity=self._map_severity(vuln.get("Severity")),
                                    message=f"Podatność w {vuln.get('PkgName')} ({vuln.get('InstalledVersion')}): {vuln.get('Title') or vuln.get('Description')[:150]}",
                                    file_path=target,
                                    fix_suggestion=f"Zaktualizuj do wersji {vuln.get('FixedVersion') or 'najnowszej'}"
                                ))
                                
                            # 2. Przetwarzanie błędów konfiguracji (Misconfigurations)
                            for config in result.get("Misconfigurations", []):
                                misconfigs_count += 1
                                issues.append(QualityIssue(
                                    id=config.get("ID"),
                                    engine="Trivy",
                                    severity=self._map_severity(config.get("Severity")),
                                    message=f"Błąd konfiguracji IaC: {config.get('Title')} - {config.get('Message')}",
                                    file_path=target,
                                    fix_suggestion=config.get("Resolution")
                                ))
                except Exception as e:
                    self.logger.error(f"Error parsing trivy report: {e}")
            
            # Trivy usually exits with 0 on success, or 1 if vulnerabilities are found and --exit-code 1 is specified (we didn't specify --exit-code 1, so it should be 0)
            if exit_code != 0 and not os.path.exists(report_file):
                err_msg = stderr.decode().strip() or f"Trivy failed with exit code {exit_code}"
                self.logger.error(f"Trivy error: {err_msg}")
                return ScanReport(
                    project=self.project_path.split("/")[-1],
                    score=0.0,
                    issues=[QualityIssue(
                        engine="Trivy",
                        severity=Severity.HIGH,
                        message=f"Błąd uruchomienia trivy: {err_msg[:200]}",
                        fix_suggestion="Sprawdź instalację trivy."
                    )],
                    metrics={"error": err_msg},
                    verdict=Verdict.ERROR
                )
            
            # Simple score calculation: 1.0 minus penalty for critical/high issues
            high_critical_count = sum(1 for issue in issues if issue.severity in [Severity.HIGH, Severity.CRITICAL])
            score = 1.0 - (high_critical_count * 0.1) - (len(issues) * 0.02)
            score = max(0.0, score)
            
            return ScanReport(
                project=self.project_path.split("/")[-1],
                score=score,
                issues=issues,
                metrics={
                    "vulnerabilities": vulns_count,
                    "misconfigurations": misconfigs_count,
                    "total_security_issues": len(issues)
                },
                verdict=Verdict.PASSED if score >= 0.70 else Verdict.REJECTED
            )
            
        except Exception as e:
            self.logger.error(f"TrivyEngine exception: {e}")
            return ScanReport(
                project=self.project_path.split("/")[-1],
                score=0.0,
                issues=[],
                metrics={"error": str(e)},
                verdict=Verdict.ERROR
            )
            
    def _map_severity(self, trivy_sev: str) -> Severity:
        mapping = {
            "LOW": Severity.LOW,
            "MEDIUM": Severity.MEDIUM,
            "HIGH": Severity.HIGH,
            "CRITICAL": Severity.CRITICAL
        }
        return mapping.get(trivy_sev, Severity.LOW)
