# engines/testing/mutation.py
import asyncio
import os
import sqlite3
from core.base_engine import BaseQualityEngine
from models.report import ScanReport, QualityIssue, Severity, Verdict

class MutationEngine(BaseQualityEngine):
    """Silnik testów mutacyjnych za pomocą mutmut."""
    
    async def run(self) -> ScanReport:
        self.logger.info(f"Starting Mutation Testing (mutmut) for {self.project_path}")
        
        # Cleanup old cache to ensure clean run
        cache_file = ".mutmut-cache"
        if os.path.exists(cache_file):
            try:
                os.remove(cache_file)
            except:
                pass
                
        try:
            # We construct the command
            cmd = ["mutmut", "run"]
            
            # Identify path to mutate
            if os.path.isfile(self.project_path):
                cmd.append(f"--paths-to-mutate={self.project_path}")
            else:
                # Default to packages or src if present
                src_path = os.path.join(self.project_path, "src")
                if os.path.exists(src_path):
                    cmd.append(f"--paths-to-mutate={src_path}")
                else:
                    cmd.append(f"--paths-to-mutate={self.project_path}")
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()
            exit_code = process.returncode
            self.logger.info(f"mutmut exited with code {exit_code}")
            
            # Extract results from sqlite cache
            killed = 0
            survived = 0
            issues = []
            
            if os.path.exists(cache_file):
                try:
                    conn = sqlite3.connect(cache_file)
                    cursor = conn.cursor()
                    cursor.execute("SELECT status, count(*) FROM mutant GROUP BY status")
                    rows = cursor.fetchall()
                    results = {row[0]: row[1] for row in rows}
                    conn.close()
                    
                    killed = results.get("killed", 0) + results.get("timeout", 0)
                    survived = results.get("survived", 0) + results.get("suspicious", 0)
                    
                    # Log survived mutants as issues
                    if survived > 0:
                        issues.append(QualityIssue(
                            id="SURVIVED_MUTANT",
                            engine="Mutation",
                            severity=Severity.HIGH,
                            message=f"Wykryto {survived} ocalałych mutantów. Testy jednostkowe nie pokrywają w pełni logiki warunkowej/brzegowej.",
                            fix_suggestion="Dopisz testy jednostkowe asercjami sprawdzającymi skrajne przypadki i warunki brzegowe."
                        ))
                except Exception as e:
                    self.logger.error(f"Error querying mutmut sqlite cache: {e}")
            
            total = killed + survived
            score = killed / total if total > 0 else 1.0
            
            # Quality Gate threshold: mutation score must be >= 0.85 (survival rate <= 15%)
            verdict = Verdict.PASSED if score >= 0.85 else Verdict.REJECTED
            
            # If mutmut was not installed or failed to run completely
            if exit_code != 0 and total == 0:
                err_msg = stderr.decode().strip() or f"mutmut failed with exit code {exit_code}"
                self.logger.error(f"mutmut critical failure: {err_msg}")
                return ScanReport(
                    project=self.project_path.split("/")[-1],
                    score=0.0,
                    issues=[QualityIssue(
                        engine="Mutation",
                        severity=Severity.HIGH,
                        message=f"Błąd uruchomienia mutmut: {err_msg[:200]}",
                        fix_suggestion="Upewnij się, że mutmut jest zainstalowany i skonfigurowany w projekcie."
                    )],
                    metrics={"error": err_msg},
                    verdict=Verdict.ERROR
                )
                
            return ScanReport(
                project=self.project_path.split("/")[-1],
                score=score,
                issues=issues,
                metrics={"killed_mutants": killed, "survived_mutants": survived, "mutation_score": score},
                verdict=verdict
            )
            
        except Exception as e:
            self.logger.error(f"MutationEngine exception: {e}")
            return ScanReport(
                project=self.project_path.split("/")[-1],
                score=0.0,
                issues=[],
                metrics={"error": str(e)},
                verdict=Verdict.ERROR
            )
