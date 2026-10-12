# packages/rae-quality/engines/governance/defect_tracker.py
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional
from models.risk import DefectItem, DefectMetrics, RiskSeverity

class DefectTracker:
    """
    Tracks defects across CI pipelines and production environments,
    calculating Defect Escape Rate, Severity-Weighted Defects, Regression Rate, and MTTR.
    """

    SEVERITY_WEIGHTS = {
        RiskSeverity.P0: 100,
        RiskSeverity.P1: 25,
        RiskSeverity.P2: 5,
        RiskSeverity.P3: 1,
    }

    def __init__(self):
        self._defects: List[DefectItem] = []

    def register_defect(
        self,
        title: str,
        severity: RiskSeverity,
        detected_at: str,  # "CI" or "PRODUCTION"
        system: str,
        resolved_at: Optional[datetime] = None
    ) -> DefectItem:
        defect = DefectItem(
            title=title,
            severity=severity,
            detected_at=detected_at.upper(),
            system=system,
            resolved_at=resolved_at
        )
        self._defects.append(defect)
        return defect

    def calculate_metrics(self) -> DefectMetrics:
        total = len(self._defects)
        if total == 0:
            return DefectMetrics(
                total_defects=0,
                production_defects=0,
                ci_defects=0,
                defect_escape_rate=0.0,
                severity_weighted_score=0,
                regression_rate=0.0,
                mttr_hours=0.0
            )

        prod_count = sum(1 for d in self._defects if d.detected_at == "PRODUCTION")
        ci_count = total - prod_count
        escape_rate = (prod_count / total) * 100.0

        weighted_score = sum(self.SEVERITY_WEIGHTS.get(d.severity, 1) for d in self._defects)

        # MTTR calculation for resolved defects
        resolved = [d for d in self._defects if d.resolved_at is not None]
        if resolved:
            total_duration_hours = sum(
                (d.resolved_at - d.created_at).total_seconds() / 3600.0
                for d in resolved
            )
            mttr = total_duration_hours / len(resolved)
        else:
            mttr = 0.0

        # Regression rate: proportion of production defects
        regression_rate = round((prod_count / max(1, total)) * 100.0, 2)

        return DefectMetrics(
            total_defects=total,
            production_defects=prod_count,
            ci_defects=ci_count,
            defect_escape_rate=round(escape_rate, 2),
            severity_weighted_score=weighted_score,
            regression_rate=regression_rate,
            mttr_hours=round(mttr, 2)
        )
