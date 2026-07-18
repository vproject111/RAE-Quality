# engines/testing/schemathesis.py
import asyncio
import os
import xml.etree.ElementTree as ET
from core.base_engine import BaseQualityEngine
from models.report import ScanReport, QualityIssue, Severity, Verdict

class SchemathesisEngine(BaseQualityEngine):
    """Silnik testowania kontraktów API (Contract Testing & Fuzzing) za pomocą Schemathesis."""
    
    async def run(self) -> ScanReport:
        target_url = os.getenv("SCHEMATHESIS_TARGET_URL", "http://localhost:8000/openapi.json")
        self.logger.info(f"Starting Schemathesis API Fuzzing against: {target_url}")
        
        report_file = "schemathesis_report.xml"
        if os.path.exists(report_file):
            try:
                os.remove(report_file)
            except:
                pass
                
        try:
            # Uruchomienie Schemathesis z zapisem raportu JUnit XML
            cmd = ["schemathesis", "run", "--junit-xml=" + report_file, "--checks", "all", target_url]
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()
            exit_code = process.returncode
            self.logger.info(f"Schemathesis exited with code {exit_code}")
            
            issues = []
            failures_count = 0
            errors_count = 0
            
            if os.path.exists(report_file):
                try:
                    tree = ET.parse(report_file)
                    root = tree.getroot()
                    # Parse testsuite details
                    for testcase in root.findall(".//testcase"):
                        failure = testcase.find("failure")
                        error = testcase.find("error")
                        
                        if failure is not None:
                            failures_count += 1
                            issues.append(QualityIssue(
                                id="API_CONTRACT_VIOLATION",
                                engine="Schemathesis",
                                severity=Severity.HIGH,
                                message=f"Naruszenie kontraktu API w {testcase.get('name')}: {failure.text[:200]}",
                                fix_suggestion="Popraw walidację danych wejściowych w kontrolerze FastAPI lub dostosuj schemat OpenAPI."
                            ))
                        if error is not None:
                            errors_count += 1
                            issues.append(QualityIssue(
                                id="API_FUZZING_ERROR",
                                engine="Schemathesis",
                                severity=Severity.CRITICAL,
                                message=f"Krytyczny błąd/crash API w {testcase.get('name')}: {error.text[:200]}",
                                fix_suggestion="Zabezpiecz kod przed nieobsłużonymi wyjątkami (500 Internal Server Error)."
                            ))
                except Exception as e:
                    self.logger.error(f"Error parsing schemathesis XML: {e}")
            
            # Schemathesis exits with non-zero if issues are found or connection failed
            if exit_code != 0 and not os.path.exists(report_file):
                err_msg = stderr.decode().strip() or f"Schemathesis failed with exit code {exit_code}"
                self.logger.error(f"Schemathesis execution failure: {err_msg}")
                return ScanReport(
                    project=self.project_path.split("/")[-1],
                    score=0.0,
                    issues=[QualityIssue(
                        engine="Schemathesis",
                        severity=Severity.HIGH,
                        message=f"Błąd uruchomienia Schemathesis: {err_msg[:200]}",
                        fix_suggestion="Upewnij się, że schemat OpenAPI pod adresem /openapi.json jest dostępny."
                    )],
                    metrics={"error": err_msg},
                    verdict=Verdict.ERROR
                )
                
            total_issues = failures_count + errors_count
            score = 1.0 - (total_issues * 0.1)
            score = max(0.0, score)
            
            return ScanReport(
                project=self.project_path.split("/")[-1],
                score=score,
                issues=issues,
                metrics={"api_failures": failures_count, "api_errors": errors_count, "api_score": score},
                verdict=Verdict.PASSED if score >= 0.85 else Verdict.REJECTED
            )
            
        except Exception as e:
            self.logger.error(f"SchemathesisEngine exception: {e}")
            return ScanReport(
                project=self.project_path.split("/")[-1],
                score=0.0,
                issues=[],
                metrics={"error": str(e)},
                verdict=Verdict.ERROR
            )
