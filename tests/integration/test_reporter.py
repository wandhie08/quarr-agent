"""Integration test: report generation from a populated state."""

import json

import pytest

from quarr.core.reporter import (
    generate_executive_summary, generate_technical_report, export_json,
)


@pytest.mark.integration
def test_executive_and_technical_reports(populated_state):
    exec_sum = generate_executive_summary(populated_state)
    tech = generate_technical_report(populated_state)
    assert "EXECUTIVE" in exec_sum
    assert "TECHNICAL" in tech
    # The confirmed finding should appear in the technical report.
    assert "SQL Injection" in tech


@pytest.mark.integration
def test_json_export_roundtrips(populated_state, tmp_path):
    path = tmp_path / "findings.json"
    export_json(populated_state, str(path))
    data = json.loads(path.read_text())
    assert isinstance(data, dict)
