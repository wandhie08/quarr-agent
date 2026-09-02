"""Unit tests for the knowledge base (Phase 3, Req 3.5)."""

import pytest

from quarr.knowledge.base import retrieve_knowledge, get_cwe_for_finding, get_cvss_range


@pytest.mark.unit
def test_retrieve_knowledge_returns_content():
    k = retrieve_knowledge(phase="exploit", query="sql injection")
    assert isinstance(k, str)
    assert len(k) > 0


@pytest.mark.unit
def test_cwe_for_sql_injection():
    cwe = get_cwe_for_finding("SQL Injection")
    assert cwe["id"] == "CWE-89"


@pytest.mark.unit
def test_cvss_range_returns_value():
    rng = get_cvss_range("SQL Injection")
    assert rng is not None
