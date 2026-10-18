"""
Re-export of ASTInspector for backward compatibility and canonical path specification.
"""
import sys
from pathlib import Path

# Ensure quality package is in sys.path
QUALITY_ROOT = Path(__file__).resolve().parent.parent
if str(QUALITY_ROOT) not in sys.path:
    sys.path.insert(0, str(QUALITY_ROOT))

from engines.testing.ast_inspector import ASTInspector, QualityIssue, Severity

__all__ = ["ASTInspector", "QualityIssue", "Severity"]
