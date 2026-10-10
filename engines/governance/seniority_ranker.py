"""
SeniorityRanker module for RAE-Quality.
Evaluates code maturity and seniority level based on coverage, complexity, and type safety.
"""

class SeniorityRanker:
    """Calculates code quality score and classifies seniority level (Junior to Advanced Senior)."""
    
    @staticmethod
    def calculate_score(coverage: float, complexity: float, type_safety: float) -> float:
        # Score formula: 0.4*Coverage + 0.3*(1 - ComplexityRatio) + 0.3*TypeSafety
        # Normalize complexity ratio assuming max complexity threshold of 30
        complexity_ratio = min(complexity / 30.0, 1.0)
        score = 0.4 * coverage + 0.3 * (1.0 - complexity_ratio) + 0.3 * type_safety
        return round(score, 4)

    @staticmethod
    def classify_level(score: float) -> str:
        if score >= 0.90:
            return "Advanced Senior"
        elif score >= 0.75:
            return "Senior"
        elif score >= 0.60:
            return "Mid Developer"
        return "Junior Developer"
