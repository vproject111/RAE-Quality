"""
AST Inspector for RAE-Quality (Silicon Oracle v3.0).
Provides deterministic, sub-20ms AST analysis for code complexity, type safety,
and test integrity without external LLM dependencies.
"""

import ast
from typing import Dict, Any, List, Optional
from models.report import QualityIssue, Severity

class ASTInspector:
    """
    Analyzes Python source code using the standard AST library to derive
    cyclomatic complexity, type safety ratio, and structural integrity.
    """

    @classmethod
    def analyze_code(cls, code: str, file_path: Optional[str] = None) -> Dict[str, Any]:
        """
        Parses code string and calculates structural metrics.
        Returns a dictionary with complexity, type_safety, and detected issues.
        """
        issues: List[QualityIssue] = []

        try:
            tree = ast.parse(code)
        except SyntaxError as e:
            return {
                "is_valid_syntax": False,
                "syntax_error": str(e),
                "complexity": 30.0,
                "type_safety": 0.0,
                "issues": [
                    QualityIssue(
                        engine="ASTInspector",
                        severity=Severity.CRITICAL,
                        message=f"SyntaxError at line {e.lineno}: {e.msg}",
                        file_path=file_path,
                        line_number=e.lineno
                    )
                ]
            }

        # 1. Cyclomatic Complexity Calculation
        complexity, max_fn_complexity = cls._calculate_complexity(tree)

        # 2. Type Safety Ratio Calculation
        type_safety, total_params, typed_params = cls._calculate_type_safety(tree)

        # 3. Detection of Antipatterns (Silent exception swallowing, eval, exec)
        antipattern_issues = cls._detect_antipatterns(tree, file_path)
        issues.extend(antipattern_issues)

        # 4. Check for TODOs / FIXMEs in code
        if "TODO" in code.upper() or "FIXME" in code.upper():
            issues.append(
                QualityIssue(
                    engine="ASTInspector",
                    severity=Severity.LOW,
                    message="Code contains pending placeholders (TODO/FIXME).",
                    file_path=file_path
                )
            )

        # 5. Check Test Integrity (if test file)
        is_test_code = file_path and ("test_" in file_path or "_test" in file_path)
        if not is_test_code and any(fn.name.startswith("test_") for fn in ast.walk(tree) if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef))):
            is_test_code = True

        if is_test_code:
            test_issues = cls._verify_test_integrity(tree, file_path)
            issues.extend(test_issues)

        return {
            "is_valid_syntax": True,
            "complexity": round(complexity, 2),
            "max_function_complexity": max_fn_complexity,
            "type_safety": round(type_safety, 4),
            "total_params": total_params,
            "typed_params": typed_params,
            "issues": issues
        }

    @staticmethod
    def _calculate_complexity(tree: ast.AST) -> tuple[float, int]:
        """
        Calculates average and maximum cyclomatic complexity per function or overall module.
        Base complexity = 1. Every decision point increments by 1.
        """
        functions = [node for node in ast.walk(tree) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))]
        
        if not functions:
            # Module-level complexity
            module_branches = 1
            for node in ast.walk(tree):
                if isinstance(node, (ast.If, ast.For, ast.AsyncFor, ast.While, ast.ExceptHandler, ast.With, ast.AsyncWith)):
                    module_branches += 1
                elif isinstance(node, ast.BoolOp):
                    module_branches += len(node.values) - 1
                elif isinstance(node, ast.IfExp):
                    module_branches += 1
            return float(module_branches), module_branches

        complexities = []
        for fn in functions:
            fn_branches = 1
            for node in ast.walk(fn):
                if isinstance(node, (ast.If, ast.For, ast.AsyncFor, ast.While, ast.ExceptHandler, ast.With, ast.AsyncWith)):
                    fn_branches += 1
                elif isinstance(node, ast.BoolOp):
                    fn_branches += len(node.values) - 1
                elif isinstance(node, ast.IfExp):
                    fn_branches += 1
            complexities.append(fn_branches)

        avg_complexity = sum(complexities) / len(complexities)
        max_complexity = max(complexities)
        return float(avg_complexity), max_complexity

    @staticmethod
    def _calculate_type_safety(tree: ast.AST) -> tuple[float, int, int]:
        """
        Calculates ratio of type-annotated parameters and return types across all functions.
        """
        functions = [node for node in ast.walk(tree) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))]
        if not functions:
            # Check variable annotations at module level
            ann_assigns = len([node for node in ast.walk(tree) if isinstance(node, ast.AnnAssign)])
            assigns = len([node for node in ast.walk(tree) if isinstance(node, ast.Assign)])
            total = ann_assigns + assigns
            if total == 0:
                return 1.0, 0, 0
            return float(ann_assigns / total), total, ann_assigns

        total_checked = 0
        annotated_checked = 0

        for fn in functions:
            # Check return type annotation
            total_checked += 1
            if fn.returns is not None:
                annotated_checked += 1

            # Check argument annotations (exclude self and cls)
            for arg in fn.args.args:
                if arg.arg in ("self", "cls"):
                    continue
                total_checked += 1
                if arg.annotation is not None:
                    # Check if annotation is not just 'Any'
                    ann_str = ast.unparse(arg.annotation) if hasattr(ast, "unparse") else ""
                    if ann_str not in ("Any", "typing.Any"):
                        annotated_checked += 1

        if total_checked == 0:
            return 1.0, 0, 0

        ratio = annotated_checked / total_checked
        return ratio, total_checked, annotated_checked

    @staticmethod
    def _detect_antipatterns(tree: ast.AST, file_path: Optional[str]) -> List[QualityIssue]:
        """Detects exception swallowing (pass in except) and insecure calls (eval, exec)."""
        issues = []
        for node in ast.walk(tree):
            # Silent exception swallowing
            if isinstance(node, ast.ExceptHandler):
                if len(node.body) == 1 and isinstance(node.body[0], ast.Pass):
                    issues.append(
                        QualityIssue(
                            engine="ASTInspector",
                            severity=Severity.HIGH,
                            message="Anti-pattern: Silent exception swallowing (except: pass).",
                            file_path=file_path,
                            line_number=node.lineno
                        )
                    )
            # Insecure function calls
            elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                if node.func.id in ("eval", "exec"):
                    issues.append(
                        QualityIssue(
                            engine="ASTInspector",
                            severity=Severity.CRITICAL,
                            message=f"Security risk: Use of '{node.func.id}' detected.",
                            file_path=file_path,
                            line_number=node.lineno
                        )
                    )
        return issues

    @staticmethod
    def _verify_test_integrity(tree: ast.AST, file_path: Optional[str]) -> List[QualityIssue]:
        """Ensures test functions contain actual assertions and are not dummy stubs."""
        issues = []
        test_functions = [
            fn for fn in ast.walk(tree) 
            if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)) and fn.name.startswith("test_")
        ]

        for fn in test_functions:
            has_assert = False
            for child in ast.walk(fn):
                if isinstance(child, ast.Assert):
                    has_assert = True
                    break
                elif isinstance(child, ast.Call):
                    # Check for pytest.raises or mock assert_called
                    call_name = ast.unparse(child.func) if hasattr(ast, "unparse") else ""
                    if "assert" in call_name or "raises" in call_name:
                        has_assert = True
                        break

            if not has_assert:
                issues.append(
                    QualityIssue(
                        engine="TestIntegrityGuard",
                        severity=Severity.HIGH,
                        message=f"Test integrity warning: '{fn.name}' has no assertions.",
                        file_path=file_path,
                        line_number=fn.lineno
                    )
                )
        return issues
