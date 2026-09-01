"""
agent.py - QUARR Cyber Operations Agent (V1 Core Loop)

M1: Basic agentic loop (tool calling, policy, state)
M4: Finding validation (state machine auto-advance)
M5: RAG knowledge injection (context-aware)
M6: Advanced planning (recovery, phase tracking, smart context)
"""

import json
import logging
from typing import Optional, Callable, Awaitable
from datetime import datetime

from quarr.core.models import (
    PentestState, Engagement, Host, Service,
    Observation, Finding, ToolExecution,
    FindingStatus, Severity
)
from quarr.core.policy import PolicyEngine, PolicyViolation
from quarr.tools.registry import (
    TOOL_REGISTRY, get_tools_for_llm, get_tools_summary,
    get_available_tools
)
from quarr.parsers.network import parse_tool_output, NmapParser
from quarr.core.llm_client import create_llm_client, BaseLLMClient
from quarr.knowledge.base import retrieve_knowledge
from quarr.core.validator import FindingValidator


logger = logging.getLogger("quarr.agent")

# === System Prompt ===

SYSTEM_PROMPT = """You are an authorized penetration testing agent operating inside a controlled security assessment environment.

Your role is to reason about penetration-testing tasks, select appropriate security testing tools, interpret their results, validate potential findings, maintain an accurate assessment state, and produce evidence-based security findings.

CORE PRINCIPLES

1. Operate only within the explicitly defined assessment scope.
2. Never assume a target is authorized unless authorization and scope have been established by the controller.
3. Never invent scan results, vulnerabilities, credentials, services, versions, or evidence.
4. Treat tool output as observations, not automatically as confirmed vulnerabilities.
5. Distinguish clearly between: observation, hypothesis, detected issue, validated finding.
6. Prefer the least intrusive action that can answer the current question.
7. Do not repeat tools unnecessarily when equivalent evidence already exists.
8. Maintain awareness of what is known and unknown.
9. Before declaring a vulnerability confirmed, obtain sufficient evidence through an appropriate validation step.
10. Do not claim successful exploitation unless the tool output provides evidence of success.
11. Keep findings reproducible and evidence-based.
12. When the current information is insufficient, perform additional authorized discovery rather than guessing.

OPERATING LOOP

OBSERVE → INTERPRET → IDENTIFY UNKNOWN → PLAN → SELECT TOOL → EXECUTE → PARSE RESULT → UPDATE STATE → VALIDATE → REASSESS

PLANNING PRINCIPLES

When selecting the next action, consider:
- current assessment objective
- current known assets
- discovered services and technologies
- completed tests and pending tests
- relevant security knowledge
- expected information gain
- tool reliability and intrusiveness
- scope restrictions

Do not select a tool merely because it is available.

FINDING PRINCIPLES

A finding should contain: title, affected asset, severity, confidence, technical description, evidence, impact, remediation, references.

Severity and confidence are independent. If evidence is insufficient, mark the issue as unvalidated.

OUTPUT FORMAT

When a tool is required, respond with ONLY a tool call using the available tools.
When providing analysis or final results, respond with clear structured text.
Never fabricate evidence."""


MAX_AGENT_STEPS = 15


class QuarrAgent:
    """
    V1 Pentest Agent.
    
    Architecture:
    - LLM = reasoning + planning
    - Tool Layer = execution
    - Policy Layer = authorization
    - State = persistent world model
    """

    def __init__(
        self,
        model: str = None,
        engagement: Engagement = None,
        api_key: str = None,
        backend: str = None,
    ):
        self.client = create_llm_client(
            model=model,
            api_key=api_key,
            backend=backend,
        )
        self.state = PentestState()
        if engagement:
            self.state.engagement = engagement
        self.policy = PolicyEngine()

    def set_engagement(self, engagement: Engagement) -> None:
        """Set atau update engagement."""
        self.state.engagement = engagement
        logger.info(
            f"Engagement set: {engagement.name} | "
            f"Scope: {engagement.allowed_targets}"
        )

    def _build_context(self) -> list:
        """
        Build message context untuk LLM.
        
        M5 (RAG): Inject relevant security knowledge based on:
        - Current phase (derived from completed tools)
        - Discovered services
        - Discovered technologies
        - Current findings
        M6: Smart context — only include what's relevant
        """
        # Determine current phase
        phase = self._detect_phase()

        # Gather services and technologies from state
        services = []
        technologies = []
        for h in self.state.hosts:
            for s in h.services:
                if s.name:
                    services.append(s.name)
                if s.product:
                    technologies.append(s.product)

        # Get finding types
        finding_types = [f.title.split()[0].lower() for f in self.state.findings]

        # M5: Retrieve relevant knowledge
        knowledge = retrieve_knowledge(
            phase=phase,
            services=services,
            technologies=technologies,
            finding_type=finding_types[0] if finding_types else None,
            query=self.state.current_objective,
        )

        state_context = f"""CURRENT STATE
{self.state.summary()}

{get_tools_summary()}"""

        if knowledge:
            state_context += f"\n\n{knowledge}"

        return [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "system", "content": state_context},
        ]

    def _detect_phase(self) -> Optional[str]:
        """M6: Detect current pentest phase from tool history."""
        if not self.state.tool_history:
            return "recon"

        tool_categories = []
        for t in self.state.tool_history:
            meta = TOOL_REGISTRY.get(t.tool_name)
            if meta:
                tool_categories.append(meta.category)

        # Latest category determines phase
        if "exploit" in tool_categories:
            return "exploit"
        if "vuln_scan" in tool_categories:
            return "vuln_scan"
        if "discovery" in tool_categories:
            return "discovery"
        return "recon"

    def _update_state_from_result(
        self,
        tool_name: str,
        args: dict,
        parsed_result: dict,
        raw_output: str,
    ) -> None:
        """Update pentest state berdasarkan parsed tool result."""
        target = args.get("target", "unknown")

        # --- Recon ---

        if tool_name == "target_scope_check":
            reachable = "[TIMEOUT]" not in raw_output and "[ERROR]" not in raw_output
            self.state.add_observation(Observation(
                source_tool=tool_name,
                description=f"Target {target} is {'reachable' if reachable else 'NOT reachable'}",
                confidence=0.95 if reachable else 0.8,
            ))

        elif tool_name == "network_discovery":
            for host_data in parsed_result.get("hosts", []):
                self.state.add_host(Host(
                    address=host_data["address"],
                    hostname=host_data.get("hostname"),
                ))
            self.state.add_observation(Observation(
                source_tool=tool_name,
                description=f"Network discovery on {target}: found {parsed_result.get('total_up', 0)} host(s)",
                confidence=0.9,
            ))

        elif tool_name == "service_enumeration":
            host_addr = parsed_result.get("host") or target
            services_data = parsed_result.get("services", [])
            if host_addr:
                services = [
                    Service(
                        host=host_addr, port=s["port"],
                        protocol=s.get("protocol", "tcp"),
                        name=s.get("name"), version=s.get("version"),
                        product=s.get("product"), state=s.get("state", "open"),
                    )
                    for s in services_data
                ]
                self.state.add_host(Host(
                    address=host_addr,
                    hostname=parsed_result.get("hostname"),
                    os=parsed_result.get("os_detection"),
                    services=services,
                ))
            self.state.add_observation(Observation(
                source_tool=tool_name,
                description=f"Service enumeration on {host_addr}: found {len(services_data)} open service(s)",
                confidence=0.9,
            ))

        elif tool_name == "subdomain_enum":
            subdomains = parsed_result.get("subdomains", [])
            self.state.add_observation(Observation(
                source_tool=tool_name,
                description=f"Subdomain enumeration on {target}: found {len(subdomains)} subdomain(s)",
                raw_evidence=", ".join(subdomains[:20]),
                confidence=0.85,
            ))

        elif tool_name == "web_fingerprint":
            techs = parsed_result.get("technologies", [])
            tech_str = ", ".join(
                f"{t['name']}" + (f" {t['version']}" if t.get('version') else "")
                for t in techs[:10]
            )
            self.state.add_observation(Observation(
                source_tool=tool_name,
                description=f"Web fingerprint on {target}: {tech_str or 'no technologies detected'}",
                confidence=0.9,
            ))

        elif tool_name == "waf_detection":
            self.state.add_observation(Observation(
                source_tool=tool_name,
                description=f"WAF detection on {target}: {parsed_result.get('summary', 'completed')}",
                confidence=0.8,
            ))

        # --- Discovery ---

        elif tool_name == "web_content_discovery":
            entries = parsed_result.get("entries", [])
            self.state.add_observation(Observation(
                source_tool=tool_name,
                description=f"Content discovery on {target}: found {len(entries)} path(s)",
                raw_evidence=", ".join(e["path"] for e in entries[:15]),
                confidence=0.9,
            ))

        elif tool_name == "web_crawl":
            self.state.add_observation(Observation(
                source_tool=tool_name,
                description=f"Web crawl on {target}: {parsed_result.get('summary', 'completed')}",
                confidence=0.85,
            ))

        elif tool_name == "parameter_discovery":
            self.state.add_observation(Observation(
                source_tool=tool_name,
                description=f"Parameter discovery on {target}: {parsed_result.get('summary', 'completed')}",
                confidence=0.8,
            ))

        # --- Vulnerability Scanning ---

        elif tool_name == "vulnerability_scan":
            findings = parsed_result.get("findings", [])
            by_sev = parsed_result.get("by_severity", {})
            sev_str = ", ".join(f"{k}: {v}" for k, v in by_sev.items())
            self.state.add_observation(Observation(
                source_tool=tool_name,
                description=f"Vulnerability scan on {target}: {len(findings)} issue(s) ({sev_str})",
                confidence=0.85,
            ))
            # Auto-create findings for critical/high
            for f in findings:
                sev = f.get("severity", "info")
                if sev in ("critical", "high"):
                    from models import FindingStatus, Severity
                    severity_map = {
                        "critical": Severity.CRITICAL, "high": Severity.HIGH,
                        "medium": Severity.MEDIUM, "low": Severity.LOW,
                    }
                    self.state.add_finding(Finding(
                        title=f.get("name", f.get("template_id", "Unknown")),
                        severity=severity_map.get(sev, Severity.INFO),
                        confidence=0.7,
                        status=FindingStatus.DETECTED,
                        asset=f.get("matched_at", target),
                        description=f.get("description", ""),
                        references=f.get("reference", []) if isinstance(f.get("reference"), list) else [],
                    ))

        elif tool_name in ("web_vuln_scan", "ssl_scan", "cms_scan"):
            self.state.add_observation(Observation(
                source_tool=tool_name,
                description=f"{tool_name} on {target}: {parsed_result.get('summary', 'completed')}",
                confidence=0.8,
            ))

        # --- Exploitation ---

        elif tool_name == "sqli_scan":
            vuln = parsed_result.get("vulnerable", False)
            params = parsed_result.get("parameters", [])
            self.state.add_observation(Observation(
                source_tool=tool_name,
                description=f"SQLi scan on {target}: {'VULNERABLE' if vuln else 'not vulnerable'}"
                    + (f" (params: {', '.join(params)})" if params else ""),
                confidence=0.9 if vuln else 0.7,
            ))
            if vuln:
                from models import FindingStatus, Severity
                self.state.add_finding(Finding(
                    title=f"SQL Injection on {target}",
                    severity=Severity.CRITICAL,
                    confidence=0.9,
                    status=FindingStatus.DETECTED,
                    asset=target,
                    description=f"SQL injection detected. DBMS: {parsed_result.get('dbms', 'unknown')}. Parameters: {', '.join(params)}",
                    evidence=parsed_result.get("injection_types", []),
                ))

        elif tool_name == "xss_scan":
            self.state.add_observation(Observation(
                source_tool=tool_name,
                description=f"XSS scan on {target}: {parsed_result.get('summary', 'completed')}",
                confidence=0.8,
            ))

        elif tool_name == "command_injection_scan":
            self.state.add_observation(Observation(
                source_tool=tool_name,
                description=f"Command injection scan on {target}: {parsed_result.get('summary', 'completed')}",
                confidence=0.8,
            ))

        elif tool_name == "bruteforce_login":
            creds = parsed_result.get("credentials", [])
            self.state.add_observation(Observation(
                source_tool=tool_name,
                description=f"Brute-force on {target}: {len(creds)} credential(s) found",
                confidence=0.95 if creds else 0.7,
            ))
            if creds:
                from models import FindingStatus, Severity
                self.state.add_finding(Finding(
                    title=f"Weak credentials on {target} ({args.get('service', 'unknown')})",
                    severity=Severity.HIGH,
                    confidence=0.95,
                    status=FindingStatus.CONFIRMED,
                    asset=target,
                    description=f"Valid credentials found via brute-force on {args.get('service', 'unknown')}",
                    evidence=[f"{c['username']}:{c['password']}" for c in creds],
                ))

        elif tool_name == "exploit_search":
            self.state.add_observation(Observation(
                source_tool=tool_name,
                description=f"Exploit search for '{args.get('query', '')}': {parsed_result.get('summary', 'completed')}",
                confidence=0.9,
            ))

        # --- Network Enum ---

        elif tool_name in ("smb_enum", "dns_enum", "snmp_enum"):
            self.state.add_observation(Observation(
                source_tool=tool_name,
                description=f"{tool_name} on {target}: {parsed_result.get('summary', 'completed')}",
                confidence=0.85,
            ))

        # --- M8: Mobile ---

        elif tool_name.startswith("apk_") or tool_name.startswith("adb_") or tool_name in ("frida_ssl_bypass", "objection_explore"):
            self._update_mobile_state(tool_name, args, parsed_result, raw_output)

        # --- Fallback ---
        else:
            self.state.add_observation(Observation(
                source_tool=tool_name,
                description=f"{tool_name} on {target}: completed",
                confidence=0.5,
            ))

    # === M8: Mobile state updates ===

    def _update_mobile_state(self, tool_name, args, parsed, raw_output):
        """Handle mobile tool state updates."""
        if tool_name == "apk_decompile":
            self.state.add_observation(Observation(
                source_tool=tool_name,
                description=f"APK decompiled: {parsed.get('summary', 'completed')}",
                confidence=0.95,
            ))

        elif tool_name == "apk_secrets_scan":
            total = parsed.get("total_secrets", 0)
            endpoints = parsed.get("total_endpoints", 0)
            self.state.add_observation(Observation(
                source_tool=tool_name,
                description=f"Secrets scan: {total} secret(s), {endpoints} API endpoint(s)",
                confidence=0.9,
            ))
            if total > 0:
                self.state.add_finding(Finding(
                    title="Hardcoded Secrets in APK Source",
                    severity=Severity.HIGH,
                    confidence=0.9,
                    status=FindingStatus.DETECTED,
                    asset=args.get("directory", "APK"),
                    description=f"Found {total} hardcoded secret(s) in decompiled source code",
                    evidence=[s.get("content", "")[:100] for s in parsed.get("secrets", [])[:5]],
                ))

        elif tool_name == "apk_manifest_analysis":
            findings = parsed.get("findings", [])
            by_sev = parsed.get("by_severity", {})
            self.state.add_observation(Observation(
                source_tool=tool_name,
                description=f"Manifest analysis: {len(findings)} finding(s) ({by_sev})",
                confidence=0.95,
            ))
            for f in findings:
                sev = f.get("severity", "info")
                if sev in ("critical", "high"):
                    severity_map = {"critical": Severity.CRITICAL, "high": Severity.HIGH}
                    self.state.add_finding(Finding(
                        title=f"Android Manifest: {f['description'][:60]}",
                        severity=severity_map.get(sev, Severity.MEDIUM),
                        confidence=0.95,
                        status=FindingStatus.CONFIRMED,
                        asset=args.get("apk_decoded_dir", "APK"),
                        description=f["description"],
                    ))

        elif tool_name == "adb_storage_check":
            sensitive = parsed.get("sensitive_data", [])
            self.state.add_observation(Observation(
                source_tool=tool_name,
                description=f"Storage check: {parsed.get('summary', 'completed')}",
                confidence=0.9,
            ))
            if sensitive:
                self.state.add_finding(Finding(
                    title="Insecure Data Storage on Device",
                    severity=Severity.HIGH,
                    confidence=0.9,
                    status=FindingStatus.DETECTED,
                    asset=args.get("package", "app"),
                    description=f"Sensitive data found in plaintext storage",
                    evidence=sensitive[:5],
                ))

        else:
            self.state.add_observation(Observation(
                source_tool=tool_name,
                description=f"{tool_name}: {parsed.get('summary', 'completed')}",
                confidence=0.8,
            ))

    async def run(
        self,
        user_query: str,
        status_callback: Optional[Callable[[str], Awaitable[None]]] = None,
    ) -> str:
        """
        Jalankan agent loop.

        M1: Basic loop (tool -> parse -> state -> repeat)
        M4: Auto-validate findings after each tool execution
        M5: Inject relevant knowledge in tool results
        M6: Recovery on tool failure, phase-aware planning
        """
        self.state.current_objective = user_query

        messages = self._build_context()
        messages.append({"role": "user", "content": user_query})

        tools_for_llm = get_tools_for_llm()
        consecutive_errors = 0
        max_consecutive_errors = 3
        failed_tools = set()

        for step in range(MAX_AGENT_STEPS):
            logger.info(f"=== Agent Step {step + 1}/{MAX_AGENT_STEPS} ===")

            try:
                response = await self.client.chat(
                    messages=messages,
                    tools=tools_for_llm,
                    max_tokens=1024,
                )
            except Exception as e:
                consecutive_errors += 1
                logger.error(f"LLM error: {e}")
                if consecutive_errors >= max_consecutive_errors:
                    return f"⚠️ Error komunikasi dengan LLM: {e}"
                messages.append({
                    "role": "user",
                    "content": (
                        "LLM communication error. "
                        "Provide a brief answer based on existing data, "
                        "or select a single tool to continue."
                    )
                })
                continue

            consecutive_errors = 0
            content = response["content"]
            tool_calls = response["tool_calls"]

            if tool_calls:
                tc = tool_calls[0]
                func_data = tc.get("function", tc)
                tool_name = func_data.get("name", "")
                arguments = func_data.get("arguments", {})

                if isinstance(arguments, str):
                    try:
                        arguments = json.loads(arguments)
                    except json.JSONDecodeError:
                        arguments = {}

                logger.info(f"Tool call: {tool_name}({arguments})")

                if status_callback:
                    await status_callback(
                        f"⚙️ Step {step + 1}: {tool_name}({json.dumps(arguments)})"
                    )

                # M6: Skip if same tool+args already failed
                tool_key = f"{tool_name}:{json.dumps(arguments, sort_keys=True)}"
                if tool_key in failed_tools:
                    messages.append({"role": "assistant", "content": content})
                    messages.append({
                        "role": "user",
                        "content": (
                            f"[SKIP] {tool_name} already failed with these arguments. "
                            f"Choose a different tool or provide analysis."
                        )
                    })
                    continue

                tool_meta = TOOL_REGISTRY.get(tool_name)
                if not tool_meta:
                    messages.append({"role": "assistant", "content": content})
                    messages.append({
                        "role": "user",
                        "content": f"[TOOL ERROR] Unknown tool '{tool_name}'. Available: {get_available_tools()}"
                    })
                    continue

                try:
                    self.policy.authorize(tool_name, arguments, self.state.engagement)
                except PolicyViolation as e:
                    logger.warning(f"Policy violation: {e}")
                    messages.append({"role": "assistant", "content": content})
                    messages.append({"role": "user", "content": f"[POLICY VIOLATION] {str(e)}"})
                    continue

                try:
                    raw_output = tool_meta.handler(**arguments)
                except TypeError as e:
                    raw_output = f"[PARAMETER ERROR] {e}"
                except Exception as e:
                    raw_output = f"[EXECUTION ERROR] {e}"

                is_error = "[ERROR]" in raw_output or "[TIMEOUT]" in raw_output
                if is_error:
                    failed_tools.add(tool_key)

                parsed = parse_tool_output(tool_name, raw_output)

                execution = ToolExecution(
                    tool_name=tool_name,
                    arguments=arguments,
                    result_summary=parsed.get("raw_summary", "") or parsed.get("summary", ""),
                    raw_output_length=len(raw_output),
                    success=not is_error,
                )
                self.state.record_tool(execution)
                self._update_state_from_result(tool_name, arguments, parsed, raw_output)

                # M4: Auto-validate findings
                validation_actions = FindingValidator.auto_validate_findings(self.state)
                if validation_actions:
                    logger.info(f"Auto-validation: {validation_actions}")

                # Build response
                messages.append({"role": "assistant", "content": content})

                # M5: knowledge for context
                phase = self._detect_phase()
                svcs = [s.name for h in self.state.hosts for s in h.services if s.name]
                techs = [s.product for h in self.state.hosts for s in h.services if s.product]
                knowledge = retrieve_knowledge(phase=phase, services=svcs, technologies=techs)

                parts = [
                    f"[TOOL RESULT: {tool_name}]",
                    json.dumps(parsed, indent=2, default=str),
                ]
                if is_error:
                    parts.append(f"\n[TOOL FAILED] {tool_name} failed. Try a different approach.")
                if validation_actions:
                    parts.append(f"\n[FINDING VALIDATION] {'; '.join(validation_actions)}")
                parts.append(f"\nUPDATED STATE:\n{self.state.summary()}")
                if knowledge:
                    parts.append(f"\n{knowledge}")

                messages.append({"role": "user", "content": "\n".join(parts)})
                continue

            else:
                if content:
                    FindingValidator.auto_validate_findings(self.state)
                    return content
                else:
                    messages.append({
                        "role": "user",
                        "content": "Please provide your analysis or select a tool."
                    })
                    continue

        # Max steps — force conclusion
        FindingValidator.auto_validate_findings(self.state)
        messages.append({
            "role": "user",
            "content": (
                "FINAL INSTRUCTION: Provide your conclusion NOW based on all "
                "collected information. Do NOT call any more tools. "
                "Include all findings and evidence."
            )
        })
        try:
            final = await self.client.chat(messages=messages, max_tokens=2048)
            return final["content"] or "⚠️ Agent could not produce a conclusion."
        except Exception:
            return f"⚠️ Batas iterasi tercapai.\n\nSTATE AKHIR:\n{self.state.summary()}"
        self,
