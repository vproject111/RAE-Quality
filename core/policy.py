# core/policy.py
import os
import yaml
from pydantic import BaseModel, Field
from typing import List

class QualityPolicy(BaseModel):
    min_coverage: float = Field(default=0.80, ge=0.0, le=1.0)
    min_type_safety: float = Field(default=0.85, ge=0.0, le=1.0)
    min_mutation_score: float = Field(default=0.85, ge=0.0, le=1.0)
    max_complexity: float = Field(default=15.0, ge=0.0)
    min_score: float = Field(default=0.70, ge=0.0, le=1.0)
    allowed_severities: List[str] = Field(default=["low", "medium"])

def load_quality_policy(policy_path: str = None) -> QualityPolicy:
    if not policy_path:
        policy_path = os.getenv("QUALITY_POLICY_PATH", "quality_policy.yaml")
    
    # Try finding in current directory first
    if not os.path.exists(policy_path):
        # Fallback to relative to this module
        fallback_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "quality_policy.yaml")
        if os.path.exists(fallback_path):
            policy_path = fallback_path

    if os.path.exists(policy_path):
        try:
            with open(policy_path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}
                # Handle nested key if quality_gate is top-level
                policy_data = data.get("quality_gate", data)
                return QualityPolicy(**policy_data)
        except Exception as e:
            raise ValueError(f"Nieprawidłowy format polityki jakości {policy_path}: {e}")
    
    # Return default policy if file is not found
    return QualityPolicy()
