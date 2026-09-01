# Architecture — QUARR Agent

Technical architecture and system design documentation.

---

## Table of Contents

1. [System Overview](#1-system-overview)
2. [Core Components](#2-core-components)
3. [Data Flow](#3-data-flow)
4. [Tool Execution Pipeline](#4-tool-execution-pipeline)
5. [LLM Integration](#5-llm-integration)
6. [State Management](#6-state-management)
7. [Knowledge Base](#7-knowledge-base)
8. [Security Model](#8-security-model)
9. [Extension Points](#9-extension-points)

---

## 1. System Overview

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

### High-Level Architecture

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

## 2. Core Components

### 2.1 Agent Loop (`quarr/core/agent.py`)

The brain of QUARR. Manages the autonomous execution cycle.

```python
class Agent:
    def __init__(self, llm_client, policy, knowledge_base):
        self.llm = llm_client
        self.policy = policy
        self.knowledge = knowledge_base
        self.state = EngagementState()
        self.max_steps = 15
    
    def run(self, user_query: str) -> AgentResult:
        """Main agent loop."""
        for step in range(self.max_steps):
            # 1. Build context
            context = self._build_context(user_query)
            
            # 2. Get LLM decision
            decision = self.llm.get_next_action(context)
            
            # 3. Check if done
            if decision.is_final_answer:
                return self._finalize(decision.answer)
            
            # 4. Validate against policy
            if not self.policy.authorize(decision.tool_call):
                continue
            
            # 5. Execute tool
            result = self._execute_tool(decision.tool_call)
            
            # 6. Update state
            self._update_state(result)
            
            # 7. Validate findings
            self._validate_findings()
        
        return self._finalize("Max steps reached")
```

### 2.2 LLM Client (`quarr/core/llm_client.py`)

Handles communication with LLM backends.

```python
class LLMClient:
    def __init__(self, backend: str = "auto"):
        self.backend = self._detect_backend(backend)
        self.model = self._get_model()
    
    def get_next_action(self, context: Context) -> Decision:
        """Get next action from LLM."""
        messages = self._build_messages(context)
        
        if self.backend == "openai":
            response = self._call_openai(messages)
        else:
            response = self._call_ollama(messages)
        
        return self._parse_decision(response)
```

### 2.3 Tool Registry (`quarr/tools/registry.py`)

Central registry of all available tools.

```python
TOOL_REGISTRY = {
    "tool_name": {
        "name": "tool_name",
        "description": "What the tool does",
        "parameters": {...},
        "handler": handler_function,
        "kali_tool": "underlying_command",
        "risk_level": "low|medium|high|critical",
        "category": "recon|discovery|...",
        "requires_scope": True
    },
    # ... 92 tools total
}

def execute_tool(name: str, params: dict) -> ToolResult:
    """Execute a registered tool."""
    tool = TOOL_REGISTRY[name]
    handler = tool["handler"]
    return handler(params)
```

### 2.4 Policy Engine (`quarr/core/policy.py`)

Enforces scope and authorization rules.

```python
class PolicyEngine:
    def __init__(self, scope: Scope):
        self.scope = scope
    
    def authorize(self, tool_call: ToolCall) -> bool:
        """Check if tool call is authorized."""
        # Extract target from parameters
        target = self._extract_target(tool_call)
        
        # Check against scope
        if not self.scope.contains(target):
            return False
        
        # Check risk level
        if tool_call.risk_level == "critical":
            return self._confirm_critical_action(tool_call)
        
        return True
```

### 2.5 Finding Validator (`quarr/core/validator.py`)

Manages finding lifecycle through state machine.

```python
class FindingValidator:
    """
    Finding States:
    OBSERVATION → HYPOTHESIS → DETECTED → VALIDATING → CONFIRMED → REPORTED
    """
    
    def validate(self, finding: Finding, evidence: Evidence) -> Finding:
        """Progress finding through validation states."""
        if finding.status == FindingStatus.DETECTED:
            if self._has_sufficient_evidence(finding, evidence):
                finding.status = FindingStatus.CONFIRMED
                finding.cwe = self._enrich_cwe(finding)
        
        return finding
```

### 2.6 Reporter (`quarr/core/reporter.py`)

Generates reports in multiple formats.

```python
class Reporter:
    def generate_executive(self, state: EngagementState) -> str:
        """Generate executive summary (non-technical)."""
        pass
    
    def generate_technical(self, state: EngagementState) -> str:
        """Generate technical report (full details)."""
        pass
    
    def export_json(self, state: EngagementState) -> dict:
        """Export findings as JSON."""
        pass
```

---

## 3. Data Flow

### Request Flow

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

### Context Building

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

## 4. Tool Execution Pipeline

```
Tool Call Request
        │
        ▼
┌───────────────────┐
│  Policy Check     │  Is target in scope?
└─────────┬─────────┘
          │
          ▼
┌───────────────────┐
│  Parameter Valid  │  Are all required params present?
└─────────┬─────────┘
          │
          ▼
┌───────────────────┐
│  Tool Handler     │  Execute the actual tool
│  (subprocess)     │
└─────────┬─────────┘
          │
          ▼
┌───────────────────┐
│  Output Parser    │  Parse raw output to structured data
└─────────┬─────────┘
          │
          ▼
┌───────────────────┐
│  State Update     │  Update hosts, services, observations
└─────────┬─────────┘
          │
          ▼
┌───────────────────┐
│  Finding Extract  │  Extract potential findings
└─────────┬─────────┘
          │
          ▼
┌───────────────────┐
│  Evidence Collect │  Store evidence for findings
└───────────────────┘
```

### Tool Handler Example

```python
def nmap_handler(params: dict) -> dict:
    """Execute nmap scan."""
    target = params["target"]
    profile = params.get("profile", "basic")
    
    # Build command
    cmd = ["nmap"]
    if profile == "full":
        cmd.extend(["-sV", "-sC", "-p-"])
    elif profile == "stealth":
        cmd.extend(["-sS", "-T2"])
    else:
        cmd.extend(["-sV", "-sC"])
    cmd.append(target)
    
    # Execute
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

## 5. LLM Integration

### OpenAI Integration

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

### Ollama Integration

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

### Prompt Structure

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

## 6. State Management

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
        """Save state to disk."""
        path = f"engagements/{state.id}/state.json"
        with open(path, "w") as f:
            json.dump(state.to_dict(), f)
    
    def load(self, engagement_id: str) -> EngagementState:
        """Load state from disk."""
        path = f"engagements/{engagement_id}/state.json"
        with open(path) as f:
            data = json.load(f)
        return EngagementState.from_dict(data)
```

---

## 7. Knowledge Base

### Knowledge Structure

```python
KNOWLEDGE_BASE = {
    "owasp_wstg": [...],      # 17 web testing guides
    "owasp_api": [...],       # 5 API security entries
    "owasp_mobile": [...],    # 10 mobile entries
    "cwe": [...],             # 10 weakness definitions
    "cvss": [...],            # 5 severity levels
    "nist_ir": [...],         # 7 incident response phases
    "nist_forensic": [...],   # Forensic guidelines
    "mitre_attack": [...],    # 10 techniques + detection
    "tech_tips": [...]        # Service-specific tips
}
```

### Context-Aware Retrieval

```python
def get_relevant(self, query: str, state: EngagementState) -> list:
    """Get relevant knowledge based on context."""
    relevant = []
    
    # Phase-based
    if state.phase == "recon":
        relevant.extend(self._get_recon_knowledge())
    
    # Technology-based
    for service in state.services:
        if service.name == "wordpress":
            relevant.extend(self._get_wordpress_knowledge())
    
    # Query-based (semantic search)
    relevant.extend(self._semantic_search(query))
    
    return relevant[:10]  # Limit to top 10
```

---

## 8. Security Model

### Scope Enforcement

```
┌─────────────────────────────────────────┐
│              POLICY ENGINE               │
├─────────────────────────────────────────┤
│                                          │
│  Tool Call: sqli_scan                   │
│  Target: https://example.com/page?id=1  │
│                                          │
│  ┌────────────────────────────────────┐ │
│  │ 1. Extract hostname: example.com   │ │
│  │ 2. Check scope.targets             │ │
│  │ 3. Check scope.excludes            │ │
│  │ 4. Verify risk level               │ │
│  └────────────────────────────────────┘ │
│                                          │
│  Result: AUTHORIZED / DENIED             │
│                                          │
└─────────────────────────────────────────┘
```

### Risk Levels

| Level | Tools | Confirmation |
|-------|-------|--------------|
| Low | Passive recon | Auto |
| Medium | Active scanning | Auto |
| High | Exploitation attempts | Warning |
| Critical | Credential dumping, RCE | Explicit confirm |

---

## 9. Extension Points

### Adding New Tools

1. Create handler in `quarr/tools/`
2. Register in `TOOL_REGISTRY`
3. Add parser if needed
4. Update documentation

### Adding New LLM Backend

```python
class CustomLLMClient(BaseLLMClient):
    def call(self, messages: list) -> str:
        # Implement custom LLM call
        pass
```

### Adding New Knowledge

```python
# Add to quarr/knowledge/base.py
KNOWLEDGE_BASE["new_category"] = [
    {
        "id": "NEW-001",
        "title": "New Knowledge Entry",
        "description": "...",
        "references": [...]
    }
]
```

### Custom Report Templates

```python
class CustomReporter(BaseReporter):
    def generate(self, state: EngagementState) -> str:
        # Custom report format
        pass
```
