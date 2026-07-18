# RAE-Quality/tests/test_iteration3.py
import pytest
from unittest.mock import AsyncMock, patch, MagicMock, mock_open
from engines.testing.mutation import MutationEngine
from engines.testing.schemathesis import SchemathesisEngine
from models.report import Verdict, Severity
import os
import json
import xml.etree.ElementTree as ET

@pytest.mark.asyncio
async def test_mutation_engine_passes_with_high_score():
    """MutationEngine should pass if mutation score is >= 0.85."""
    mock_process = AsyncMock()
    mock_process.returncode = 0
    mock_process.communicate.return_value = (b"", b"")
    
    # We mock sqlite3 to simulate 17 killed mutants and 2 survived (score = 17/19 = ~0.89)
    mock_conn = MagicMock()
    mock_cursor = MagicMock()
    mock_cursor.fetchall.return_value = [("killed", 17), ("survived", 2)]
    mock_conn.cursor.return_value = mock_cursor
    
    with patch("asyncio.create_subprocess_exec", return_value=mock_process), \
         patch("os.path.exists", return_value=True), \
         patch("sqlite3.connect", return_value=mock_conn):
         
        engine = MutationEngine(project_path="/tmp/test-project")
        report = await engine.run()
        
        assert report.verdict == Verdict.PASSED
        assert report.score == pytest.approx(17 / 19)
        assert len(report.issues) == 1
        assert "2 ocalałych" in report.issues[0].message

@pytest.mark.asyncio
async def test_mutation_engine_rejects_with_low_score():
    """MutationEngine should reject if mutation score is < 0.85."""
    mock_process = AsyncMock()
    mock_process.returncode = 0
    mock_process.communicate.return_value = (b"", b"")
    
    # We mock sqlite3 to simulate 10 killed mutants and 10 survived (score = 10/20 = 0.50)
    mock_conn = MagicMock()
    mock_cursor = MagicMock()
    mock_cursor.fetchall.return_value = [("killed", 10), ("survived", 10)]
    mock_conn.cursor.return_value = mock_cursor
    
    with patch("asyncio.create_subprocess_exec", return_value=mock_process), \
         patch("os.path.exists", return_value=True), \
         patch("sqlite3.connect", return_value=mock_conn):
         
        engine = MutationEngine(project_path="/tmp/test-project")
        report = await engine.run()
        
        assert report.verdict == Verdict.REJECTED
        assert report.score == 0.50
        assert len(report.issues) == 1

@pytest.mark.asyncio
async def test_schemathesis_engine_detects_contract_violations():
    """SchemathesisEngine should parse JUnit XML report and flag failures/errors."""
    mock_process = AsyncMock()
    mock_process.returncode = 1
    mock_process.communicate.return_value = (b"", b"")
    
    xml_report = """<?xml version="1.0" encoding="utf-8"?>
    <testsuite name="schemathesis" tests="2" failures="1" errors="1">
        <testcase name="GET /v2/quality/audit" time="0.1">
            <failure message="500 Internal Server Error">Response status code was 500</failure>
        </testcase>
        <testcase name="GET /health" time="0.05">
            <error message="Connection Refused">Could not connect to target</error>
        </testcase>
    </testsuite>
    """
    
    with patch("asyncio.create_subprocess_exec", return_value=mock_process), \
         patch("os.path.exists", lambda path: True if "schemathesis_report.xml" in path else False), \
         patch("xml.etree.ElementTree.parse") as mock_parse:
         
        mock_root = ET.fromstring(xml_report)
        mock_tree = MagicMock()
        mock_tree.getroot.return_value = mock_root
        mock_parse.return_value = mock_tree
        
        engine = SchemathesisEngine(project_path="/tmp/test-project")
        report = await engine.run()
        
        assert report.verdict == Verdict.REJECTED
        assert report.score == 0.80 # 1.0 - 2 * 0.1
        assert len(report.issues) == 2
        assert any("Naruszenie kontraktu API" in issue.message for issue in report.issues)
        assert any("Krytyczny błąd/crash API" in issue.message for issue in report.issues)
