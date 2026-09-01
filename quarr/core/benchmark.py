"""
benchmark.py - M13: Benchmark & Metrics

Test agent accuracy against known lab targets.
Measure: tool selection, finding recall, false positives, efficiency.
"""

import json
import time
import logging
from datetime import datetime
from typing import List, Dict, Optional
from dataclasses import dataclass, field

from quarr.core.models import PentestState, FindingStatus

logger = logging.getLogger("quarr.benchmark")


@dataclass
class ExpectedFinding:
    title: str
    severity: str
    asset: str
    keywords: List[str] = field(default_factory=list)


@dataclass
class BenchmarkTarget:
    name: str
    targets: List[str]
    expected_findings: List[ExpectedFinding] = field(default_factory=list)
    expected_services: List[str] = field(default_factory=list)


@dataclass
class BenchmarkResult:
    target_name: str
    start_time: str
    end_time: str
    duration_seconds: float

    # Tool metrics
    total_tool_calls: int = 0
    successful_tool_calls: int = 0
    failed_tool_calls: int = 0

    # Finding metrics
    expected_findings: int = 0
    found_findings: int = 0
    false_positives: int = 0
    missed_findings: int = 0

    # Calculated
    finding_recall: float = 0.0          # found / expected
    false_positive_rate: float = 0.0     # FP / total found
    tool_efficiency: float = 0.0         # findings / tool calls
    tool_success_rate: float = 0.0       # successful / total

    # Details
    matched: List[str] = field(default_factory=list)
    missed: List[str] = field(default_factory=list)
    extra: List[str] = field(default_factory=list)

    def summary(self) -> str:
        lines = [
            f"📊 BENCHMARK: {self.target_name}",
            f"Duration: {self.duration_seconds:.1f}s",
            f"",
            f"Tool Calls: {self.total_tool_calls} ({self.successful_tool_calls} OK, {self.failed_tool_calls} failed)",
            f"Tool Success Rate: {self.tool_success_rate:.0%}",
            f"",
            f"Expected Findings: {self.expected_findings}",
            f"Found: {self.found_findings}",
            f"Missed: {self.missed_findings}",
            f"False Positives: {self.false_positives}",
            f"",
            f"Finding Recall: {self.finding_recall:.0%}",
            f"False Positive Rate: {self.false_positive_rate:.0%}",
            f"Efficiency: {self.tool_efficiency:.2f} findings/tool",
        ]
        if self.matched:
            lines.append(f"\n✅ Matched: {', '.join(self.matched)}")
        if self.missed:
            lines.append(f"❌ Missed: {', '.join(self.missed)}")
        if self.extra:
            lines.append(f"⚠️ Extra: {', '.join(self.extra)}")
        return "\n".join(lines)


def evaluate(state: PentestState, benchmark: BenchmarkTarget, duration: float) -> BenchmarkResult:
    """Evaluate agent results against expected benchmark."""

    result = BenchmarkResult(
        target_name=benchmark.name,
        start_time="",
        end_time="",
        duration_seconds=duration,
        expected_findings=len(benchmark.expected_findings),
    )

    # Tool metrics
    result.total_tool_calls = len(state.tool_history)
    result.successful_tool_calls = sum(1 for t in state.tool_history if t.success)
    result.failed_tool_calls = result.total_tool_calls - result.successful_tool_calls
    if result.total_tool_calls > 0:
        result.tool_success_rate = result.successful_tool_calls / result.total_tool_calls

    # Finding matching
    agent_findings = state.findings
    matched_expected = set()

    for exp in benchmark.expected_findings:
        found = False
        for af in agent_findings:
            title_match = any(
                kw.lower() in af.title.lower() or kw.lower() in (af.description or "").lower()
                for kw in exp.keywords
            )
            if title_match:
                found = True
                matched_expected.add(exp.title)
                result.matched.append(exp.title)
                break
        if not found:
            result.missed.append(exp.title)

    result.found_findings = len(result.matched)
    result.missed_findings = len(result.missed)

    # False positives = agent findings not in expected
    for af in agent_findings:
        is_expected = any(
            any(kw.lower() in af.title.lower() or kw.lower() in (af.description or "").lower()
                for kw in exp.keywords)
            for exp in benchmark.expected_findings
        )
        if not is_expected:
            result.extra.append(af.title)
    result.false_positives = len(result.extra)

    # Calculated metrics
    if result.expected_findings > 0:
        result.finding_recall = result.found_findings / result.expected_findings
    total_found = result.found_findings + result.false_positives
    if total_found > 0:
        result.false_positive_rate = result.false_positives / total_found
    if result.total_tool_calls > 0:
        result.tool_efficiency = result.found_findings / result.total_tool_calls

    return result


# ============================================================
# Pre-defined Benchmark Targets
# ============================================================

BENCHMARK_TARGETS = {
    "dvwa": BenchmarkTarget(
        name="DVWA (Damn Vulnerable Web Application)",
        targets=["dvwa.local"],
        expected_findings=[
            ExpectedFinding("SQL Injection", "critical", "dvwa.local", ["sql injection", "sqli"]),
            ExpectedFinding("XSS", "high", "dvwa.local", ["xss", "cross-site scripting"]),
            ExpectedFinding("Command Injection", "critical", "dvwa.local", ["command injection", "rce"]),
            ExpectedFinding("File Upload", "high", "dvwa.local", ["file upload", "unrestricted"]),
        ],
        expected_services=["http", "mysql"],
    ),
    "metasploitable2": BenchmarkTarget(
        name="Metasploitable 2",
        targets=["metasploitable.local"],
        expected_findings=[
            ExpectedFinding("FTP Anonymous", "medium", "metasploitable.local", ["ftp", "anonymous"]),
            ExpectedFinding("Weak SSH", "high", "metasploitable.local", ["ssh", "weak", "credential"]),
            ExpectedFinding("SMB Vuln", "critical", "metasploitable.local", ["smb", "samba", "ms17"]),
            ExpectedFinding("MySQL Default", "high", "metasploitable.local", ["mysql", "default", "root"]),
        ],
        expected_services=["ftp", "ssh", "http", "smb", "mysql"],
    ),
    "juice-shop": BenchmarkTarget(
        name="OWASP Juice Shop",
        targets=["juice-shop.local"],
        expected_findings=[
            ExpectedFinding("SQL Injection", "critical", "juice-shop.local", ["sql injection", "sqli"]),
            ExpectedFinding("XSS", "medium", "juice-shop.local", ["xss", "cross-site"]),
            ExpectedFinding("Broken Auth", "high", "juice-shop.local", ["auth", "jwt", "token"]),
            ExpectedFinding("IDOR", "high", "juice-shop.local", ["idor", "access control", "bola"]),
        ],
        expected_services=["http"],
    ),
}


def save_benchmark_result(result: BenchmarkResult, filepath: str = "benchmark_results.json"):
    """Append benchmark result to file."""
    results = []
    if os.path.exists(filepath):
        with open(filepath) as f:
            results = json.load(f)

    results.append({
        "target": result.target_name,
        "timestamp": datetime.now().isoformat(),
        "duration": result.duration_seconds,
        "metrics": {
            "finding_recall": result.finding_recall,
            "false_positive_rate": result.false_positive_rate,
            "tool_efficiency": result.tool_efficiency,
            "tool_success_rate": result.tool_success_rate,
        },
        "matched": result.matched,
        "missed": result.missed,
        "extra": result.extra,
    })

    with open(filepath, "w") as f:
        json.dump(results, f, indent=2)


import os
