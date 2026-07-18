# engines/security/gitleaks.py
import asyncio
import json
import os
from core.base_engine import BaseQualityEngine
from models.report import ScanReport, QualityIssue, Severity, Verdict

class GitleaksEngine(BaseQualityEngine):
    """Silnik skanowania sekretów i kluczy API za pomocą Gitleaks."""
    
    async def run(self) -> ScanReport:
        self.logger.info("Starting Gitleaks Scan...")
        report_file = "gitleaks_report.json"
        
        # Cleanup old report
        if os.path.exists(report_file):
            try:
                os.remove(report_file)
            except:
                pass

        try:
            # Uruchomienie Gitleaks w trybie detect (no-git dla czystego skanu plików, lub normalnym jeśli .git istnieje)
            cmd = ["gitleaks", "detect", "--source", self.project_path, "--report", report_file, "-v"]
            
            # Jeśli projekt nie ma .git (lub jest podkatalogiem), użyj flags --no-git
            git_dir = os.path.join(self.project_path, ".git")
            if not os.path.exists(git_dir):
                cmd.append("--no-git")
                
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()
            
            # Gitleaks exits with 0 (no leaks), 1 (leaks found), or other (error)
            exit_code = process.returncode
            self.logger.info(f"Gitleaks exited with code {exit_code}")
            
            issues = []
            
            if os.path.exists(report_file):
                try:
                    with open(report_file, "r") as f:
                        findings = json.load(f) or []
                        for finding in findings:
                            issues.append(QualityIssue(
                                id="LEAK_DETECTED",
                                engine="Gitleaks",
                                severity=Severity.CRITICAL,
                                message=f"Wykryto wyciek sekretu ({finding.get('RuleID')}): {finding.get('Description')}",
                                file_path=finding.get("File"),
                                line_number=finding.get("StartLine"),
                                fix_suggestion="UNIEWAŻNIJ KLUCZ NATYCHMIAST. Nie wystarczy usunąć go z historii Gita - klucz musi zostać zrotowany!"
                            ))
                except Exception as e:
                    self.logger.error(f"Error parsing gitleaks report: {e}")
            
            if exit_code not in [0, 1]:
                err_msg = stderr.decode().strip() or f"Gitleaks failed with exit code {exit_code}"
                self.logger.error(f"Gitleaks error: {err_msg}")
                return ScanReport(
                    project=self.project_path.split("/")[-1],
                    score=0.0,
                    issues=[QualityIssue(
                        engine="Gitleaks",
                        severity=Severity.HIGH,
                        message=f"Błąd uruchomienia gitleaks: {err_msg[:200]}",
                        fix_suggestion="Sprawdź instalację gitleaks."
                    )],
                    metrics={"error": err_msg},
                    verdict=Verdict.ERROR
                )
            
            score = 1.0 if not issues else 0.0
            return ScanReport(
                project=self.project_path.split("/")[-1],
                score=score,
                issues=issues,
                metrics={"leaks_found": len(issues)},
                verdict=Verdict.PASSED if not issues else Verdict.REJECTED
            )
            
        except Exception as e:
            self.logger.error(f"GitleaksEngine exception: {e}")
            return ScanReport(
                project=self.project_path.split("/")[-1],
                score=0.0,
                issues=[],
                metrics={"error": str(e)},
                verdict=Verdict.ERROR
            )
