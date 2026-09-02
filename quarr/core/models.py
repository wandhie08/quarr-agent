"""
models.py - Pentest State Models (Pydantic)

Persistent world model untuk agent. Semua data yang agent ketahui
disimpan di sini sebagai structured state, bukan sebagai teks bebas.
"""

from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from enum import Enum
from datetime import datetime
import uuid


# === Enums ===

class FindingStatus(str, Enum):
    OBSERVATION = "observation"
    HYPOTHESIS = "hypothesis"
    DETECTED = "detected"
    VALIDATING = "validating"
    CONFIRMED = "confirmed"
    DISMISSED = "dismissed"
    REPORTED = "reported"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# === Core Models ===

class Service(BaseModel):
    host: str
    port: int
    protocol: str = "tcp"
    name: Optional[str] = None
    version: Optional[str] = None
    product: Optional[str] = None
    extra_info: Optional[str] = None
    state: str = "open"


class Host(BaseModel):
    address: str
    hostname: Optional[str] = None
    os: Optional[str] = None
    state: str = "up"
    services: List[Service] = []
    discovered_at: datetime = Field(default_factory=datetime.now)


class Observation(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4())[:8])
    source_tool: str
    description: str
    raw_evidence: Optional[str] = None
    confidence: float = 0.5
    timestamp: datetime = Field(default_factory=datetime.now)


class Finding(BaseModel):
    id: str = Field(default_factory=lambda: f"FIND-{str(uuid.uuid4())[:8]}")
    title: str
    severity: Severity = Severity.INFO
    confidence: float = 0.5
    status: FindingStatus = FindingStatus.OBSERVATION
    asset: str
    description: Optional[str] = None
    evidence: List[str] = []
    impact: Optional[str] = None
    remediation: Optional[str] = None
    references: List[str] = []
    observation_ids: List[str] = []


class ToolExecution(BaseModel):
    tool_name: str
    arguments: Dict[str, Any]
    result_summary: str
    raw_output_length: int = 0
    success: bool = True
    duration_ms: Optional[int] = None
    error: Optional[str] = None
    timestamp: datetime = Field(default_factory=datetime.now)


# === Engagement / Scope ===

class Engagement(BaseModel):
    id: str = Field(default_factory=lambda: f"ENG-{str(uuid.uuid4())[:8]}")
    name: str = "Unnamed Assessment"
    allowed_targets: List[str] = []
    excluded_targets: List[str] = []
    allowed_operations: List[str] = [
        "network_discovery",
        "service_enumeration",
        "target_scope_check",
    ]
    created_at: datetime = Field(default_factory=datetime.now)


# === Pentest State ===

class PentestState(BaseModel):
    engagement: Engagement = Field(default_factory=Engagement)
    hosts: List[Host] = []
    observations: List[Observation] = []
    findings: List[Finding] = []
    tool_history: List[ToolExecution] = []
    completed_tests: List[str] = []
    pending_tests: List[str] = []
    current_objective: str = "Awaiting engagement scope definition"
    notes: List[str] = []

    def add_host(self, host: Host) -> None:
        """Tambah host, update jika sudah ada."""
        for i, existing in enumerate(self.hosts):
            if existing.address == host.address:
                # Merge services
                existing_ports = {
                    (s.port, s.protocol) for s in existing.services
                }
                for svc in host.services:
                    if (svc.port, svc.protocol) not in existing_ports:
                        existing.services.append(svc)
                # Update fields jika ada info baru
                if host.hostname and not existing.hostname:
                    existing.hostname = host.hostname
                if host.os and not existing.os:
                    existing.os = host.os
                return
        self.hosts.append(host)

    def add_observation(self, obs: Observation) -> None:
        self.observations.append(obs)

    def add_finding(self, finding: Finding) -> None:
        self.findings.append(finding)

    def record_tool(self, execution: ToolExecution) -> None:
        self.tool_history.append(execution)
        tool_key = f"{execution.tool_name}({execution.arguments})"
        if tool_key not in self.completed_tests:
            self.completed_tests.append(tool_key)

    def get_host(self, address: str) -> Optional[Host]:
        for h in self.hosts:
            if h.address == address:
                return h
        return None

    def summary(self) -> str:
        """Ringkasan state untuk context LLM."""
        lines = []
        lines.append(f"ENGAGEMENT: {self.engagement.name}")
        lines.append(f"OBJECTIVE: {self.current_objective}")
        lines.append(f"SCOPE: {', '.join(self.engagement.allowed_targets) or 'Not defined'}")
        if self.engagement.excluded_targets:
            lines.append(f"EXCLUDED: {', '.join(self.engagement.excluded_targets)}")

        lines.append(f"\nDISCOVERED HOSTS ({len(self.hosts)}):")
        for h in self.hosts:
            svc_str = ""
            if h.services:
                svc_list = [
                    f"  {s.port}/{s.protocol} {s.name or '?'}"
                    + (f" ({s.version})" if s.version else "")
                    for s in h.services
                ]
                svc_str = "\n" + "\n".join(svc_list)
            lines.append(f"  {h.address}"
                         + (f" ({h.hostname})" if h.hostname else "")
                         + svc_str)

        if self.observations:
            lines.append(f"\nOBSERVATIONS ({len(self.observations)}):")
            for obs in self.observations[-5:]:  # Last 5
                lines.append(f"  [{obs.source_tool}] {obs.description}")

        if self.findings:
            lines.append(f"\nFINDINGS ({len(self.findings)}):")
            for f in self.findings:
                lines.append(
                    f"  [{f.severity.value.upper()}] {f.title} "
                    f"(status: {f.status.value}, confidence: {f.confidence})"
                )

        lines.append(f"\nCOMPLETED TOOL CALLS: {len(self.tool_history)}")
        if self.tool_history:
            for t in self.tool_history[-5:]:
                lines.append(f"  {t.tool_name}({t.arguments}) -> {'OK' if t.success else 'FAIL'}")

        if self.pending_tests:
            lines.append(f"\nPENDING: {', '.join(self.pending_tests)}")

        return "\n".join(lines)
