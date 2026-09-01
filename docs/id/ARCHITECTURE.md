# Arsitektur — QUARR Agent

Dokumentasi arsitektur teknis dan desain sistem.

---

## Daftar Isi

1. [Gambaran Sistem](#1-gambaran-sistem)
2. [Komponen Inti](#2-komponen-inti)
3. [Alur Data](#3-alur-data)
4. [Pipeline Eksekusi Tool](#4-pipeline-eksekusi-tool)
5. [Integrasi LLM](#5-integrasi-llm)
6. [Manajemen State](#6-manajemen-state)
7. [Knowledge Base](#7-knowledge-base)
8. [Model Keamanan](#8-model-keamanan)
9. [Extension Points](#9-extension-points)

---

## 1. Gambaran Sistem

```
┌─────────────────────────────────────────────────────────────────┐
│                         QUARR AGENT                              │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐  │
│  │   CLI    │───▶│  Agent   │───▶│  Tools   │───▶│  Kali    │  │
│  │ main.py  │    │  Loop    │    │ Registry │    │  Linux   │  │
│  └──────────┘    └────┬─────┘    └──────────┘    └──────────┘  │
│                       │                                         │
│                       ▼                                         │
│               ┌──────────────┐                                  │
│               │  LLM Client  │                                  │
│               │ OpenAI/Ollama│                                  │
│               └──────────────┘                                  │
│                                                                  │
│  ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐  │
│  │  Policy  │    │ Validator│    │ Reporter │    │ Persist  │  │
│  │  Engine  │    │  (M4)    │    │  (M7)    │    │  (M9)    │  │
│  └──────────┘    └──────────┘    └──────────┘    └──────────┘  │
│                                                                  │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │                    Knowledge Base (M5)                    │   │
│  │         OWASP | CWE | MITRE ATT&CK | NIST | CVSS         │   │
│  └──────────────────────────────────────────────────────────┘   │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Arsitektur High-Level

```
User Input
    │
    ▼
┌─────────────────┐
│   main.py       │  CLI Interface
│   (Entrypoint)  │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│   agent.py      │  Core Agentic Loop
│   (Orchestrator)│
└────────┬────────┘
         │
    ┌────┴────┬─────────┬─────────┬─────────┐
    ▼         ▼         ▼         ▼         ▼
┌───────┐ ┌───────┐ ┌───────┐ ┌───────┐ ┌───────┐
│  LLM  │ │ Tools │ │Policy │ │Validat│ │Report │
│Client │ │Registry│ │Engine │ │  or   │ │  er   │
└───────┘ └───────┘ └───────┘ └───────┘ └───────┘
```

---

## 2. Komponen Inti

### 2.1 Agent Loop (`quarr/core/agent.py`)

Otak dari QUARR. Mengelola siklus eksekusi otonom.

```python
class Agent:
    def __init__(self, llm_client, policy, knowledge_base):
        self.llm = llm_client
        self.policy = policy
        self.knowledge = knowledge_base
        self.state = EngagementState()
        self.max_steps = 15
    
    def run(self, user_query: str) -> AgentResult:
        """Loop utama agent."""
        for step in range(self.max_steps):
            # 1. Bangun context
            context = self._build_context(user_query)
            
            # 2. Dapatkan keputusan LLM
            decision = self.llm.get_next_action(context)
            
            # 3. Cek apakah selesai
            if decision.is_final_answer:
                return self._finalize(decision.answer)
            
            # 4. Validasi terhadap policy
            if not self.policy.authorize(decision.tool_call):
                continue
            
            # 5. Eksekusi tool
            result = self._execute_tool(decision.tool_call)
            
            # 6. Update state
            self._update_state(result)
            
            # 7. Validasi findings
            self._validate_findings()
        
        return self._finalize("Max steps tercapai")
```

### 2.2 LLM Client (`quarr/core/llm_client.py`)

Menangani komunikasi dengan backend LLM.

```python
class LLMClient:
    def __init__(self, backend: str = "auto"):
        self.backend = self._detect_backend(backend)
        self.model = self._get_model()
    
    def get_next_action(self, context: Context) -> Decision:
        """Dapatkan aksi selanjutnya dari LLM."""
        messages = self._build_messages(context)
        
        if self.backend == "openai":
            response = self._call_openai(messages)
        else:
            response = self._call_ollama(messages)
        
        return self._parse_decision(response)
```

### 2.3 Tool Registry (`quarr/tools/registry.py`)

Registry pusat untuk semua tool yang tersedia.

```python
TOOL_REGISTRY = {
    "tool_name": {
        "name": "tool_name",
        "description": "Apa yang tool lakukan",
        "parameters": {...},
        "handler": handler_function,
        "kali_tool": "underlying_command",
        "risk_level": "low|medium|high|critical",
        "category": "recon|discovery|...",
        "requires_scope": True
    },
    # ... total 92 tools
}

def execute_tool(name: str, params: dict) -> ToolResult:
    """Eksekusi tool yang terdaftar."""
    tool = TOOL_REGISTRY[name]
    handler = tool["handler"]
    return handler(params)
```

### 2.4 Policy Engine (`quarr/core/policy.py`)

Menerapkan aturan scope dan otorisasi.

```python
class PolicyEngine:
    def __init__(self, scope: Scope):
        self.scope = scope
    
    def authorize(self, tool_call: ToolCall) -> bool:
        """Cek apakah tool call diotorisasi."""
        # Ekstrak target dari parameter
        target = self._extract_target(tool_call)
        
        # Cek terhadap scope
        if not self.scope.contains(target):
            return False
        
        # Cek risk level
        if tool_call.risk_level == "critical":
            return self._confirm_critical_action(tool_call)
        
        return True
```

### 2.5 Finding Validator (`quarr/core/validator.py`)

Mengelola lifecycle finding melalui state machine.

```python
class FindingValidator:
    """
    States Finding:
    OBSERVATION → HYPOTHESIS → DETECTED → VALIDATING → CONFIRMED → REPORTED
    """
    
    def validate(self, finding: Finding, evidence: Evidence) -> Finding:
        """Progress finding melalui state validasi."""
        if finding.status == FindingStatus.DETECTED:
            if self._has_sufficient_evidence(finding, evidence):
                finding.status = FindingStatus.CONFIRMED
                finding.cwe = self._enrich_cwe(finding)
        
        return finding
```

### 2.6 Reporter (`quarr/core/reporter.py`)

Generate report dalam berbagai format.

```python
class Reporter:
    def generate_executive(self, state: EngagementState) -> str:
        """Generate ringkasan executive (non-teknis)."""
        pass
    
    def generate_technical(self, state: EngagementState) -> str:
        """Generate report teknis (detail lengkap)."""
        pass
    
    def export_json(self, state: EngagementState) -> dict:
        """Export findings sebagai JSON."""
        pass
```

---

## 3. Alur Data

### Alur Request

```
User Query
    │
    ▼
┌─────────────────────────────────────────────────────────────┐
│                     AGENT LOOP                               │
│                                                              │
│  ┌─────────┐    ┌─────────┐    ┌─────────┐    ┌─────────┐  │
│  │ Context │───▶│   LLM   │───▶│ Policy  │───▶│  Tool   │  │
│  │ Builder │    │ Decision│    │  Check  │    │ Execute │  │
│  └─────────┘    └─────────┘    └─────────┘    └────┬────┘  │
│       ▲                                            │        │
│       │                                            ▼        │
│  ┌────┴────┐    ┌─────────┐    ┌─────────┐    ┌─────────┐  │
│  │ State   │◀───│Validator│◀───│ Parser  │◀───│  Kali   │  │
│  │ Update  │    │         │    │         │    │  Tool   │  │
│  └─────────┘    └─────────┘    └─────────┘    └─────────┘  │
│                                                              │
└─────────────────────────────────────────────────────────────┘
    │
    ▼
Final Answer / Report
```

### Pembangunan Context

```python
def _build_context(self, query: str) -> Context:
    return Context(
        user_query=query,
        engagement_scope=self.scope,
        current_state=self.state,
        tool_history=self.state.tool_executions[-5:],
        findings=self.state.findings,
        knowledge=self.knowledge.get_relevant(query, self.state),
        available_tools=TOOL_REGISTRY.keys()
    )
```

---

## 4. Pipeline Eksekusi Tool

```
Tool Call Request
        │
        ▼
┌───────────────────┐
│  Policy Check     │  Apakah target dalam scope?
└─────────┬─────────┘
          │
          ▼
┌───────────────────┐
│  Parameter Valid  │  Apakah semua param required ada?
└─────────┬─────────┘
          │
          ▼
┌───────────────────┐
│  Tool Handler     │  Eksekusi tool sebenarnya
│  (subprocess)     │
└─────────┬─────────┘
          │
          ▼
┌───────────────────┐
│  Output Parser    │  Parse output mentah ke data terstruktur
└─────────┬─────────┘
          │
          ▼
┌───────────────────┐
│  State Update     │  Update hosts, services, observations
└─────────┬─────────┘
          │
          ▼
┌───────────────────┐
│  Finding Extract  │  Ekstrak potential findings
└─────────┬─────────┘
          │
          ▼
┌───────────────────┐
│  Evidence Collect │  Simpan evidence untuk findings
└───────────────────┘
```

### Contoh Tool Handler

```python
def nmap_handler(params: dict) -> dict:
    """Eksekusi nmap scan."""
    target = params["target"]
    profile = params.get("profile", "basic")
    
    # Bangun command
    cmd = ["nmap"]
    if profile == "full":
        cmd.extend(["-sV", "-sC", "-p-"])
    elif profile == "stealth":
        cmd.extend(["-sS", "-T2"])
    else:
        cmd.extend(["-sV", "-sC"])
    cmd.append(target)
    
    # Eksekusi
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    
    # Parse
    parsed = parse_nmap_output(result.stdout)
    
    return {
        "raw_output": result.stdout,
        "parsed": parsed,
        "return_code": result.returncode
    }
```

---

## 5. Integrasi LLM

### Integrasi OpenAI

```python
def _call_openai(self, messages: list) -> str:
    response = openai.ChatCompletion.create(
        model=self.model,
        messages=messages,
        functions=self._get_tool_schemas(),
        function_call="auto",
        temperature=0.1
    )
    return response.choices[0].message
```

### Integrasi Ollama

```python
def _call_ollama(self, messages: list) -> str:
    response = requests.post(
        f"{self.ollama_url}/api/chat",
        json={
            "model": self.model,
            "messages": messages,
            "stream": False
        }
    )
    return response.json()["message"]["content"]
```

### Struktur Prompt

```
SYSTEM PROMPT:
You are QUARR, an autonomous cybersecurity agent...

CONTEXT:
- Scope: {targets}
- Current phase: {phase}
- Previous tools: {history}
- Findings so far: {findings}

KNOWLEDGE:
{relevant_owasp_cwe_mitre}

USER QUERY:
{user_input}

AVAILABLE TOOLS:
{tool_schemas}
```

---

## 6. Manajemen State

### Engagement State

```python
@dataclass
class EngagementState:
    id: str
    name: str
    scope: Scope
    hosts: Dict[str, Host]
    services: List[Service]
    observations: List[Observation]
    findings: List[Finding]
    tool_executions: List[ToolExecution]
    evidence: Dict[str, Evidence]
    created_at: datetime
    updated_at: datetime
```

### Persistence

```python
class Persistence:
    def save(self, state: EngagementState) -> None:
        """Simpan state ke disk."""
        path = f"engagements/{state.id}/state.json"
        with open(path, "w") as f:
            json.dump(state.to_dict(), f)
    
    def load(self, engagement_id: str) -> EngagementState:
        """Load state dari disk."""
        path = f"engagements/{engagement_id}/state.json"
        with open(path) as f:
            data = json.load(f)
        return EngagementState.from_dict(data)
```

---

## 7. Knowledge Base

### Struktur Knowledge

```python
KNOWLEDGE_BASE = {
    "owasp_wstg": [...],      # 17 panduan web testing
    "owasp_api": [...],       # 5 entri keamanan API
    "owasp_mobile": [...],    # 10 entri mobile
    "cwe": [...],             # 10 definisi weakness
    "cvss": [...],            # 5 level severity
    "nist_ir": [...],         # 7 fase incident response
    "nist_forensic": [...],   # Panduan forensic
    "mitre_attack": [...],    # 10 teknik + deteksi
    "tech_tips": [...]        # Tips spesifik service
}
```

### Pengambilan Context-Aware

```python
def get_relevant(self, query: str, state: EngagementState) -> list:
    """Dapatkan knowledge relevan berdasarkan context."""
    relevant = []
    
    # Berdasarkan fase
    if state.phase == "recon":
        relevant.extend(self._get_recon_knowledge())
    
    # Berdasarkan teknologi
    for service in state.services:
        if service.name == "wordpress":
            relevant.extend(self._get_wordpress_knowledge())
    
    # Berdasarkan query (semantic search)
    relevant.extend(self._semantic_search(query))
    
    return relevant[:10]  # Batasi ke top 10
```

---

## 8. Model Keamanan

### Penegakan Scope

```
┌─────────────────────────────────────────┐
│              POLICY ENGINE               │
├─────────────────────────────────────────┤
│                                          │
│  Tool Call: sqli_scan                   │
│  Target: https://example.com/page?id=1  │
│                                          │
│  ┌────────────────────────────────────┐ │
│  │ 1. Ekstrak hostname: example.com   │ │
│  │ 2. Cek scope.targets               │ │
│  │ 3. Cek scope.excludes              │ │
│  │ 4. Verifikasi risk level           │ │
│  └────────────────────────────────────┘ │
│                                          │
│  Result: AUTHORIZED / DENIED             │
│                                          │
└─────────────────────────────────────────┘
```

### Level Risiko

| Level | Tools | Konfirmasi |
|-------|-------|------------|
| Rendah | Passive recon | Otomatis |
| Sedang | Active scanning | Otomatis |
| Tinggi | Percobaan eksploitasi | Warning |
| Kritikal | Credential dumping, RCE | Konfirmasi eksplisit |

---

## 9. Extension Points

### Menambahkan Tool Baru

1. Buat handler di `quarr/tools/`
2. Daftarkan di `TOOL_REGISTRY`
3. Tambahkan parser jika diperlukan
4. Update dokumentasi

### Menambahkan Backend LLM Baru

```python
class CustomLLMClient(BaseLLMClient):
    def call(self, messages: list) -> str:
        # Implementasi custom LLM call
        pass
```

### Menambahkan Knowledge Baru

```python
# Tambahkan ke quarr/knowledge/base.py
KNOWLEDGE_BASE["new_category"] = [
    {
        "id": "NEW-001",
        "title": "Entri Knowledge Baru",
        "description": "...",
        "references": [...]
    }
]
```

### Template Report Custom

```python
class CustomReporter(BaseReporter):
    def generate(self, state: EngagementState) -> str:
        # Format report custom
        pass
```
