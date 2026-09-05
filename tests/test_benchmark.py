"""Unit tests for the agent benchmark/accuracy scorer (quarr/core/benchmark.py).

benchmark.py was 0% covered — it measures how well the agent performs against
known-vulnerable targets (finding recall, false-positive rate, tool efficiency),
so its correctness directly affects how a professional judges the agent. These
tests lock down the scoring math and the empty-keywords matching fix (a bad
expected-finding definition must not silently report a correct discovery as
missed + false positive).
"""

import json

import pytest

from quarr.core.benchmark import (
    BENCHMARK_TARGETS,
    BenchmarkTarget,
    ExpectedFinding,
    evaluate,
    save_benchmark_result,
)
from quarr.core.models import Finding, PentestState, Severity, ToolExecution


def _state(findings=(), tools=()):
    st = PentestState()
    for f in findings:
        st.add_finding(f)
    for t in tools:
        st.record_tool(t)
    return st


def _tool(name, success=True):
    return ToolExecution(tool_name=name, arguments={}, result_summary="", success=success)


@pytest.mark.unit
class TestEvaluateScoring:
    def test_perfect_recall_no_false_positives(self):
        state = _state(
            findings=[
                Finding(title="SQL Injection on login", asset="a", severity=Severity.CRITICAL),
                Finding(title="Reflected XSS", asset="a", severity=Severity.HIGH),
            ],
            tools=[_tool("sqli_scan"), _tool("xss_scan")],
        )
        bench = BenchmarkTarget(name="t", targets=["a"], expected_findings=[
            ExpectedFinding("SQLi", "critical", "a", ["sql injection"]),
            ExpectedFinding("XSS", "high", "a", ["xss"]),
        ])
        r = evaluate(state, bench, duration=12.5)
        assert r.found_findings == 2 and r.missed_findings == 0
        assert r.finding_recall == 1.0
        assert r.false_positives == 0
        assert r.tool_success_rate == 1.0
        assert r.tool_efficiency == 1.0  # 2 findings / 2 tools

    def test_false_positive_detected(self):
        state = _state(findings=[
            Finding(title="SQL Injection", asset="a", severity=Severity.CRITICAL),
            Finding(title="Directory listing enabled", asset="a", severity=Severity.LOW),
        ])
        bench = BenchmarkTarget(name="t", targets=["a"], expected_findings=[
            ExpectedFinding("SQLi", "critical", "a", ["sql injection"]),
        ])
        r = evaluate(state, bench, duration=1.0)
        assert r.found_findings == 1
        assert r.false_positives == 1
        assert r.extra == ["Directory listing enabled"]
        assert r.false_positive_rate == 0.5  # 1 FP / (1 found + 1 FP)

    def test_missed_finding_lowers_recall(self):
        state = _state(findings=[
            Finding(title="SQL Injection", asset="a", severity=Severity.CRITICAL),
        ])
        bench = BenchmarkTarget(name="t", targets=["a"], expected_findings=[
            ExpectedFinding("SQLi", "critical", "a", ["sql injection"]),
            ExpectedFinding("XSS", "high", "a", ["xss"]),
        ])
        r = evaluate(state, bench, duration=1.0)
        assert r.found_findings == 1 and r.missed_findings == 1
        assert r.finding_recall == 0.5
        assert r.missed == ["XSS"]

    def test_tool_success_rate_with_failures(self):
        state = _state(tools=[_tool("a"), _tool("b", success=False), _tool("c")])
        bench = BenchmarkTarget(name="t", targets=["a"], expected_findings=[])
        r = evaluate(state, bench, duration=1.0)
        assert r.total_tool_calls == 3
        assert r.failed_tool_calls == 1
        assert round(r.tool_success_rate, 2) == 0.67

    def test_all_empty_no_division_by_zero(self):
        r = evaluate(_state(), BenchmarkTarget(name="t", targets=["a"]), duration=0.0)
        assert r.finding_recall == 0.0
        assert r.false_positive_rate == 0.0
        assert r.tool_efficiency == 0.0
        assert r.tool_success_rate == 0.0


@pytest.mark.unit
class TestEmptyKeywordsFix:
    """Regression: an expected finding with no keywords must fall back to its
    title, so a correctly-discovered issue is scored as found — not missed +
    counted as a false positive."""

    def test_empty_keywords_matches_on_title(self):
        state = _state(findings=[
            Finding(title="SQL Injection detected", asset="a", severity=Severity.CRITICAL),
        ])
        bench = BenchmarkTarget(name="t", targets=["a"], expected_findings=[
            ExpectedFinding("SQL Injection", "critical", "a", keywords=[]),
        ])
        r = evaluate(state, bench, duration=1.0)
        assert r.found_findings == 1
        assert r.finding_recall == 1.0
        assert r.missed == []
        assert r.false_positives == 0  # the correct finding is NOT a false positive


@pytest.mark.unit
class TestSummaryAndPersistence:
    def test_summary_contains_key_metrics(self):
        state = _state(
            findings=[Finding(title="SQL Injection", asset="a", severity=Severity.CRITICAL)],
            tools=[_tool("sqli_scan")],
        )
        bench = BenchmarkTarget(name="DVWA", targets=["a"], expected_findings=[
            ExpectedFinding("SQLi", "critical", "a", ["sql injection"]),
        ])
        text = evaluate(state, bench, duration=3.0).summary()
        assert "BENCHMARK: DVWA" in text
        assert "Finding Recall" in text
        assert "False Positive Rate" in text
        assert "✅ Matched" in text

    def test_save_benchmark_result_appends(self, tmp_path):
        state = _state(findings=[Finding(title="SQL Injection", asset="a")])
        bench = BenchmarkTarget(name="t", targets=["a"], expected_findings=[
            ExpectedFinding("SQLi", "critical", "a", ["sql injection"]),
        ])
        result = evaluate(state, bench, duration=1.0)
        fp = tmp_path / "bench.json"
        save_benchmark_result(result, str(fp))
        save_benchmark_result(result, str(fp))  # append second run
        data = json.loads(fp.read_text())
        assert len(data) == 2
        assert data[0]["target"] == "t"
        assert "finding_recall" in data[0]["metrics"]


@pytest.mark.unit
def test_predefined_targets_are_wellformed():
    # The shipped benchmark catalog must be usable out of the box.
    assert {"dvwa", "metasploitable2", "juice-shop"} <= set(BENCHMARK_TARGETS)
    for key, bt in BENCHMARK_TARGETS.items():
        assert bt.name and bt.targets
        assert bt.expected_findings, f"{key} has no expected findings"
        for ef in bt.expected_findings:
            assert ef.keywords, f"{key}/{ef.title} should define keywords"
