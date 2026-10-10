import pytest
from engines.testing.ast_inspector import ASTInspector

def test_ast_inspector_syntax_error():
    code = "def broken_code(: pass"
    res = ASTInspector.analyze_code(code)
    assert res["is_valid_syntax"] is False
    assert "syntax_error" in res
    assert len(res["issues"]) == 1
    assert res["issues"][0].engine == "ASTInspector"

def test_ast_inspector_clean_typed_code():
    code = '''
def add_numbers(a: int, b: int) -> int:
    """Adds two numbers."""
    if a > 0:
        return a + b
    return b
'''
    res = ASTInspector.analyze_code(code)
    assert res["is_valid_syntax"] is True
    assert res["complexity"] == 2.0  # Base 1 + 1 (if)
    assert res["type_safety"] == 1.0  # a, b, return are all typed
    assert len(res["issues"]) == 0

def test_ast_inspector_untyped_complex_code():
    code = '''
def messy_fn(x, y, z):
    if x > 0:
        for i in range(y):
            if i % 2 == 0:
                print(i)
    elif z < 0:
        while True:
            break
    return None
'''
    res = ASTInspector.analyze_code(code)
    assert res["is_valid_syntax"] is True
    assert res["complexity"] >= 5.0
    assert res["type_safety"] == 0.0  # No types on params or return

def test_ast_inspector_detects_swallowed_exceptions_and_eval():
    code = '''
def dangerous():
    try:
        eval("2 + 2")
    except Exception:
        pass
'''
    res = ASTInspector.analyze_code(code)
    assert res["is_valid_syntax"] is True
    messages = [issue.message for issue in res["issues"]]
    assert any("Silent exception swallowing" in m for m in messages)
    assert any("eval" in m for m in messages)

def test_ast_inspector_test_integrity_missing_assertions():
    code = '''
def test_something():
    x = 10
    y = 20
    # No assert!
'''
    res = ASTInspector.analyze_code(code, file_path="tests/test_example.py")
    messages = [issue.message for issue in res["issues"]]
    assert any("has no assertions" in m for m in messages)
