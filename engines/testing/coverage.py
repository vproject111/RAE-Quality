# engines/testing/coverage.py
import asyncio
import subprocess
import os
import json
from core.base_engine import BaseQualityEngine
from models.report import ScanReport, QualityIssue, Severity, Verdict

class CoverageEngine(BaseQualityEngine):
    """Silnik analizy pokrycia i generowania testów."""
    
    async def run(self) -> ScanReport:
        self.logger.info(f"Analyzing test coverage for {self.project_path}")
        
        cov_file = "coverage.json"
        # Cleanup old coverage.json to avoid stale reports
        if os.path.exists(cov_file):
            try:
                os.remove(cov_file)
                self.logger.info(f"Cleaned up old {cov_file}")
            except Exception as e:
                self.logger.warning(f"Failed to remove old {cov_file}: {e}")
        
        try:
            # Uruchomienie pytest-cov
            cmd = ["pytest", "--cov=" + self.project_path, "--cov-report=json", self.project_path]
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()
            exit_code = process.returncode
            
            self.logger.info(f"Pytest exited with code {exit_code}")
            
            # Pytest exit codes: 0 (all passed), 1 (some failed), 5 (no tests collected) are acceptable for coverage
            if exit_code not in [0, 1, 5]:
                err_msg = stderr.decode().strip() or stdout.decode().strip() or f"Pytest failed with exit code {exit_code}"
                self.logger.error(f"Pytest critical failure: {err_msg}")
                return ScanReport(
                    project=self.project_path.split("/")[-1],
                    score=0.0,
                    issues=[QualityIssue(
                        engine="Coverage",
                        severity=Severity.CRITICAL,
                        message=f"Krytyczny błąd testów (exit code {exit_code}): {err_msg[:200]}",
                        fix_suggestion="Skoryguj błędy w kodzie testów lub konfiguracji pytest."
                    )],
                    metrics={"error": err_msg, "exit_code": exit_code},
                    verdict=Verdict.ERROR
                )
            
            issues = []
            metrics = {}
            
            if os.path.exists(cov_file):
                with open(cov_file, 'r') as f:
                    data = json.load(f)
                    total_cov = data.get("totals", {}).get("percent_covered", 0)
                    metrics["total_coverage"] = total_cov
                    
                    # Generowanie issue dla plików z niskim pokryciem
                    for file, info in data.get("files", {}).items():
                        file_cov = info.get("summary", {}).get("percent_covered", 0)
                        if file_cov < 50:
                            issues.append(QualityIssue(
                                id="LOW_COVERAGE",
                                engine="Coverage",
                                severity=Severity.HIGH,
                                message=f"Krytycznie niskie pokrycie testami: {file_cov:.1f}%",
                                file_path=file,
                                fix_suggestion="Uruchom RAE-Phoenix w trybie CREATE_TEST dla tego pliku."
                            ))
                
                score = total_cov / 100.0
                return ScanReport(
                    project=self.project_path.split("/")[-1],
                    score=score,
                    issues=issues,
                    metrics=metrics,
                    verdict=Verdict.PASSED if score >= 0.70 else Verdict.REJECTED
                )
            
            self.logger.error("Pytest ran, but coverage.json was not found")
            return ScanReport(
                project=self.project_path.split("/")[-1],
                score=0.0,
                issues=[QualityIssue(
                    engine="Coverage",
                    severity=Severity.HIGH,
                    message="Brak pliku raportu coverage.json",
                    fix_suggestion="Upewnij się, że biblioteka pytest-cov jest zainstalowana i działa."
                )],
                metrics={"error": "Coverage data not found"},
                verdict=Verdict.ERROR
            )
            
        except Exception as e:
            self.logger.error(f"CoverageEngine exception: {e}")
            return ScanReport(
                project=self.project_path.split("/")[-1],
                score=0.0,
                issues=[],
                metrics={"error": str(e)},
                verdict=Verdict.ERROR
            )

