# FAQ — QUARR Agent

Frequently Asked Questions about QUARR Agent.

---

## Table of Contents

1. [General](#1-general)
2. [Installation](#2-installation)
3. [Configuration](#3-configuration)
4. [Usage](#4-usage)
5. [Tools](#5-tools)
6. [LLM / AI](#6-llm--ai)
7. [Troubleshooting](#7-troubleshooting)
8. [Security & Ethics](#8-security--ethics)

---

## 1. General

### What is QUARR Agent?

QUARR (Query-driven Unified Autonomous Red/Blue Research) Agent is an AI-powered cybersecurity tool that automates penetration testing, blue team defense, and digital forensics. It uses LLM (Large Language Models) to intelligently orchestrate 92 security tools.

### What can QUARR do?

- **Red Team (43 tools)**: Web, network, mobile, and Active Directory pentesting
- **Blue Team (19 tools)**: Defense, monitoring, threat hunting
- **Forensics (16 tools)**: Incident response, memory/disk analysis, evidence collection
- **Threat Intel (5 tools)**: VirusTotal, Shodan, AbuseIPDB integration
- **Vulnerability Assessment (4 tools)**: CIS benchmarks, hardening checks
- **SecOps (5 tools)**: Health checks, compliance, playbooks

### Is QUARR free?

QUARR Agent itself is open source. However:
- **OpenAI API** requires a paid API key
- **Ollama** is free but requires local compute resources

### What operating systems are supported?

- **Recommended**: Kali Linux (all tools pre-installed)
- **Supported**: Debian, Ubuntu (need to install Kali tools)
- **Not supported**: Windows, macOS (tools are Linux-specific)

---

## 2. Installation

### What are the minimum requirements?

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| RAM | 8 GB | 16 GB |
| Disk | 10 GB | 50 GB |
| Python | 3.10 | 3.11+ |
| OS | Kali Linux | Kali Linux (latest) |

### How do I install QUARR?

```bash
git clone https://github.com/your-repo/quarr-agent.git
cd quarr-agent
pip install -r requirements.txt
cp .env.example .env
# Edit .env with your API key
python3 main.py
```

See [INSTALLATION.md](INSTALLATION.md) for detailed instructions.

### Do I need all 92 tools installed?

No. QUARR gracefully handles missing tools:
- Agent will skip unavailable tools
- Core functionality works with basic tools (nmap, nuclei, sqlmap)
- Install tools based on your use case

### How do I install missing tools?

```bash
# Most tools are in Kali repos
sudo apt install <tool-name>

# Python tools
pip install <package>

# Check tool availability
which <tool-name>
```

---

## 3. Configuration

### How do I configure OpenAI?

Edit `.env`:

```bash
OPENAI_API_KEY=sk-proj-your-key-here
OPENAI_MODEL=gpt-4o-mini
```

### How do I use Ollama instead?

1. Install Ollama: `curl -fsSL https://ollama.com/install.sh | sh`
2. Pull a model: `ollama pull WhiteRabbitNeo/WhiteRabbitNeo-2.5-Qwen-2.5-Coder-7B`
3. Leave `OPENAI_API_KEY` empty in `.env`

### Which LLM model is best?

| Use Case | Recommended Model |
|----------|-------------------|
| General use | gpt-4o-mini (fast, cheap) |
| Complex tasks | gpt-4o (accurate) |
| Offline/Privacy | WhiteRabbitNeo (local) |
| Low resources | Llama 3.1 8B (local) |

### How do I change the max agent steps?

Edit `quarr/core/agent.py`:

```python
MAX_AGENT_STEPS = 20  # Default is 15
```

---

## 4. Usage

### How do I start a pentest?

```
🔐 quarr> Full pentest on target.com
```

The agent automatically runs reconnaissance, discovery, vulnerability scanning, and exploitation.

### How do I limit scope?

During engagement setup:

```
Assessment name: My Pentest
  + target: target.com
  + target: 10.10.10.0/24
  - exclude: 10.10.10.1
```

### How do I save and resume sessions?

```
🔐 quarr> save          # Save current session
🔐 quarr> quit          # Auto-saves on exit

# Next time:
🔐 quarr> load          # List saved sessions
Load session #: 1       # Resume session
```

### How do I generate reports?

```
🔐 quarr> report        # Executive summary (terminal)
🔐 quarr> executive     # Export executive report (markdown)
🔐 quarr> technical     # Export technical report (markdown)
🔐 quarr> export        # Export findings (JSON)
```

### How do I plan before executing?

```
🔐 quarr> plan Web pentest target.com
# Review the plan
Approve plan? (y/n): y
# Agent executes the plan
```

---

## 5. Tools

### Why does a tool fail?

Common reasons:
1. **Tool not installed**: `apt install <tool>`
2. **Missing dependencies**: Check tool documentation
3. **Permission denied**: Run with sudo or fix permissions
4. **Target not reachable**: Check network connectivity
5. **Rate limited**: Wait and retry

### How do I run a specific tool?

Ask the agent directly:

```
🔐 quarr> Run nmap scan on 192.168.1.1
🔐 quarr> SQL injection test on https://target.com/page?id=1
🔐 quarr> Check firewall status
```

### Can I add custom tools?

Yes! See [CONTRIBUTING.md](CONTRIBUTING.md) for instructions on adding new tools.

### What tools require root/sudo?

| Tool Category | Requires Root |
|---------------|---------------|
| Network capture | Yes |
| Memory dump | Yes |
| Disk imaging | Yes |
| Firewall management | Yes |
| ADB (some operations) | Yes |
| Most other tools | No |

---

## 6. LLM / AI

### How does the AI work?

1. User provides a query
2. Agent builds context (scope, state, knowledge)
3. LLM decides which tool to run
4. Tool executes and returns results
5. Agent updates state and validates findings
6. Loop continues until task complete

### Is my data sent to OpenAI?

If using OpenAI:
- Your queries and tool outputs are sent to OpenAI API
- OpenAI's data retention policies apply
- For sensitive engagements, use Ollama (fully local)

### Why does the agent sometimes make mistakes?

LLMs are probabilistic. Common issues:
- **Hallucination**: LLM invents non-existent tools
- **Wrong parameters**: Misinterprets tool syntax
- **Loops**: Gets stuck repeating same action

Solutions:
- Use better models (gpt-4o vs gpt-4o-mini)
- Provide clearer instructions
- Report issues for improvement

### How do I improve accuracy?

1. Be specific in your queries
2. Provide context (target info, constraints)
3. Use `plan` command to review before executing
4. Upgrade to more capable model

---

## 7. Troubleshooting

### "ModuleNotFoundError"

```bash
pip install -r requirements.txt
```

### "Command not found: nmap"

```bash
sudo apt install nmap
```

### "OpenAI API error"

Check:
1. API key is correct in `.env`
2. You have API credits
3. Internet connectivity

### "Ollama connection refused"

```bash
# Start Ollama server
ollama serve

# Check if running
curl http://localhost:11434/api/tags
```

### "Permission denied"

```bash
# For network tools
sudo python3 main.py

# Or fix specific permissions
sudo chmod +x /path/to/tool
```

### Agent gets stuck in a loop

1. Press Ctrl+C to interrupt
2. Try rephrasing your query
3. Use `plan` command for complex tasks
4. Check if tool is returning errors

### Sessions not saving

1. Check write permissions to `engagements/` directory
2. Ensure disk space available
3. Check for JSON errors in state file

### Tool timeout

Some tools take a long time. Options:
1. Wait for completion
2. Use faster scan profiles
3. Reduce scope

---

## 8. Security & Ethics

### Is QUARR legal to use?

QUARR is a tool. Legal use depends on:
- **You MUST have authorization** to test target systems
- Unauthorized testing is illegal in most jurisdictions
- Always get written permission before pentesting

### How do I use QUARR ethically?

1. **Only test systems you own or have permission to test**
2. Respect scope boundaries
3. Report findings responsibly
4. Don't use for malicious purposes
5. Follow your organization's policies

### What about responsible disclosure?

If you find vulnerabilities:
1. Document findings clearly
2. Report to system owner
3. Allow reasonable time for fix
4. Don't exploit or disclose publicly

### Does QUARR store credentials?

- API keys are stored in `.env` (local file)
- Captured credentials from pentesting are stored in session state
- Protect your `engagements/` directory
- Don't commit `.env` or sessions to git

### Can QUARR be used for malicious purposes?

QUARR is designed for legitimate security testing. Misuse for:
- Unauthorized access
- Data theft
- System damage
- Any illegal activity

Is strictly prohibited and may be illegal.

---

## Still Have Questions?

- Check [Documentation](README.md)
- Open a GitHub Issue
- Join community discussions

---

*Last updated: August 2026*
