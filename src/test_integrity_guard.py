import ast
from typing import Tuple, Optional, Set

class TestIntegrityGuard:
    """
    Test Integrity Guard for RAE-Quality.
    Uses AST (Abstract Syntax Tree) parsing to prevent agents from weakening
    or removing test assertions during self-repair loops.
    """

    def validate_test_integrity(
        self, baseline_code: str, proposed_code: str
    ) -> Tuple[bool, Optional[str]]:
        """
        Parses both baseline and proposed test files.
        Returns: (passed: bool, violation_reason: Optional[str])
        """
        try:
            baseline_tree = ast.parse(baseline_code)
            proposed_tree = ast.parse(proposed_code)
        except SyntaxError as e:
            return False, f"Proposed code contains syntax errors: {e}"

        # 1. Gather assertions metrics from baseline
        base_assertions = self._count_assertions(baseline_tree)
        prop_assertions = self._count_assertions(proposed_tree)

        # 2. Check for assertion drop (Assertion Deletion)
        if prop_assertions < base_assertions:
            return False, f"Test integrity violation: Assertion count dropped from {base_assertions} to {prop_assertions}."

        # 3. Check for Assert True weakening (Assertion Softening)
        base_soft = self._count_soft_assertions(baseline_tree)
        prop_soft = self._count_soft_assertions(proposed_tree)
        
        # If the count of useless assert True statements grew, it implies real asserts were replaced
        if prop_soft > base_soft:
            return False, "Test integrity violation: Assertion softening detected (empty assert True statements added)."

        return True, None

    def _count_assertions(self, tree: ast.AST) -> int:
        """Counts assert statements and self.assert* method calls in the AST."""
        count = 0
        for node in ast.walk(tree):
            # Matches standard Python `assert x == y`
            if isinstance(node, ast.Assert):
                count += 1
            # Matches unittest `self.assertEqual(...)` or pytest equivalent calls
            elif isinstance(node, ast.Call):
                if isinstance(node.func, ast.Attribute):
                    func_name = node.func.attr
                    if func_name.startswith("assert"):
                        count += 1
        return count

    def _count_soft_assertions(self, tree: ast.AST) -> int:
        """Counts empty or trivial assertions like `assert True` or `assert 1 == 1`."""
        count = 0
        for node in ast.walk(tree):
            if isinstance(node, ast.Assert):
                # Standard check for assert True
                if isinstance(node.test, ast.Constant) and node.test.value is True:
                    count += 1
                elif isinstance(node.test, ast.Name) and node.test.id == "True":
                    count += 1
                # Check for assert 1 == 1 or equivalent trivial constant comparisons
                elif isinstance(node.test, ast.Compare):
                    if (isinstance(node.test.left, ast.Constant) and 
                        len(node.test.comparators) == 1 and 
                        isinstance(node.test.comparators[0], ast.Constant)):
                        if node.test.left.value == node.test.comparators[0].value:
                            count += 1
        return count
