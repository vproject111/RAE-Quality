# RAE-Quality/tests/conftest.py
import pytest
import asyncio
import httpx
from unittest.mock import AsyncMock, patch

@pytest.fixture
def mock_rae_api():
    """Mocks the RAE API V2 for testing Tribunal without real LLM costs."""
    from unittest.mock import MagicMock
    mock_get_resp = MagicMock()
    mock_get_resp.status_code = 200
    mock_get_resp.raise_for_status = lambda: None
    
    with patch("httpx.AsyncClient.get", return_value=mock_get_resp), \
         patch("httpx.AsyncClient.post") as mock_post:
        yield mock_post

@pytest.fixture
def sample_code():
    return """
def calculate_sum(a, b):
    # TODO: Add validation
    return a + b
"""

@pytest.fixture
def clean_code():
    return """
def calculate_sum(a: int, b: int) -> int:
    \"\"\"Calculates sum of two integers.\"\"\"
    return a + b
"""
