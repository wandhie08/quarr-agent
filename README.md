# QUARR

### One Agent. Red. Blue. Forensics.

**Autonomous Cyber Operations Agent** — 97 tools across 6 security domains, powered by AI (OpenAI / Ollama).

```
                    QUARR
                      │
          ┌───────────┼───────────┐
          │           │           │
      QUARR Red   QUARR Blue   QUARR DFIR
      48 tools     19 tools     16 tools
          │           │           │
      Offensive   Defensive    Forensics
          │           │           │
          └───────────┼───────────┘
                      │
              ┌───────┼───────┐
              │       │       │
          QUARR    QUARR    QUARR
          Intel   VulnAss  SecOps
          5 tools  4 tools  5 tools
              │       │       │
              └───────┼───────┘
                      │
                AI ORCHESTRATOR
                      │
               OpenAI / Ollama
                      │
                 Kali Linux
```

## Quick Start

```bash
cd quarr-agent/v1
pip install -r requirements.txt
python3 main.py
```

```
🔐 quarr> Full pentest on target.com               # 🔴 Red
🔐 quarr> Check this server's security status      # 🔵 Blue
🔐 quarr> Investigate incident, dump memory        # 🔍 DFIR
🔐 quarr> Check IP reputation 185.220.101.34       # 🛡️ Intel
🔐 quarr> Linux security audit                     # 📋 VulnAss
🔐 quarr> Security health check                    # ⚙️ SecOps
```

## 97 Tools

| Domain | Count | Capabilities |
|--------|-------|-------------|
| 🔴 Quarr Red | 48 | Web, API, Network, Mobile, AD pentest |
| 🔵 Quarr Blue | 19 | Defense, monitoring, threat hunting |
| 🔍 Quarr DFIR | 16 | Forensic, incident response, evidence |
| 🛡️ Quarr Intel | 5 | VirusTotal, AbuseIPDB, Shodan, CVE/NVD |
| 📋 Quarr VulnAss | 4 | CIS audit, hardening, patches, config |
| ⚙️ Quarr SecOps | 5 | Health check, playbooks, metrics, compliance |

## Features

- **Full auto** — One instruction, agent runs entire pipeline
- **96 tools** — Recon → exploitation → forensics, all automated
- **Policy engine** — Every tool call validated against scope + role (RBAC)
- **Finding validation** — State machine: observation → confirmed
- **Three knowledge layers** — static RAG (OWASP/CWE/MITRE/NIST) · methodology
  playbooks (THP3, OWASP MASTG, Hacking APIs, …) · cross-engagement learning
- **Cross-engagement learning** — records confirmed findings + tool effectiveness
  and reuses them on future targets ([LEARNING.md](docs/en/LEARNING.md))
- **API security testing** — OWASP API Top 10: BOLA, data exposure, JWT analysis
- **Threat intelligence** — VirusTotal, AbuseIPDB, Shodan, NVD
- **IR playbooks** — Brute force, malware, data breach, web attack
- **Reports** — Executive, technical (markdown), findings (JSON)
- **Persistent state** — Save/load/resume sessions
- **Attack planner** — Plan → review → execute flow
- **Retesting** — Verify remediation
- **Compliance** — CIS Benchmark, PCI-DSS, HIPAA (basic)
- **Multi-backend** — OpenAI + Ollama, auto-detect
- **Secure by design** — no-shell execution, argument allowlist, secret redaction,
  path-traversal & injection guards ([SECURITY.md](SECURITY.md))

## Docs

### 🇺🇸 English

| Document | Content |
|----------|---------|
| [INSTALLATION.md](docs/en/INSTALLATION.md) | Installation & setup guide |
| [USAGE.md](docs/en/USAGE.md) | Full guide — all 97 tools, setup, config |
| [PENTEST_GUIDE.md](docs/en/PENTEST_GUIDE.md) | Red/Blue/Forensic step-by-step |
| [MOBILE.md](docs/en/MOBILE.md) | Mobile pentest (APK + device) |
| [ACTIVE_DIRECTORY.md](docs/en/ACTIVE_DIRECTORY.md) | Active Directory pentest guide |
| [BLUE_TEAM_DFIR.md](docs/en/BLUE_TEAM_DFIR.md) | Blue team, DFIR, threat hunting |
| [API_REFERENCE.md](docs/en/API_REFERENCE.md) | Complete tools reference |
| [ARCHITECTURE.md](docs/en/ARCHITECTURE.md) | System architecture & design |
| [LEARNING.md](docs/en/LEARNING.md) | Cross-engagement learning (agent gets smarter) |
| [METHODOLOGY.md](docs/en/METHODOLOGY.md) | Reference playbooks (THP3, MASTG, Hacking APIs, …) |
| [TESTING.md](docs/en/TESTING.md) | Test tiers & how to run them (incl. live) |
| [SECURITY.md](SECURITY.md) | Security model, guarantees & limitations |
| [CONTRIBUTING.md](docs/en/CONTRIBUTING.md) | Contribution guidelines |
| [CHANGELOG.md](docs/en/CHANGELOG.md) | Version history |
| [FAQ.md](docs/en/FAQ.md) | Frequently asked questions |

### 🇮🇩 Bahasa Indonesia

| Dokumen | Isi |
|---------|-----|
| [INSTALLATION.md](docs/id/INSTALLATION.md) | Panduan instalasi & setup |
| [USAGE.md](docs/id/USAGE.md) | Panduan lengkap — 97 tools, setup, konfigurasi |
| [PENTEST_GUIDE.md](docs/id/PENTEST_GUIDE.md) | Panduan step-by-step Red/Blue/Forensic |
| [MOBILE.md](docs/id/MOBILE.md) | Mobile pentest (APK + device) |
| [ACTIVE_DIRECTORY.md](docs/id/ACTIVE_DIRECTORY.md) | Panduan pentest Active Directory |
| [BLUE_TEAM_DFIR.md](docs/id/BLUE_TEAM_DFIR.md) | Blue team, DFIR, threat hunting |
| [API_REFERENCE.md](docs/id/API_REFERENCE.md) | Referensi lengkap tools |
| [ARCHITECTURE.md](docs/id/ARCHITECTURE.md) | Arsitektur & desain sistem |
| [CONTRIBUTING.md](docs/id/CONTRIBUTING.md) | Panduan kontribusi |
| [CHANGELOG.md](docs/id/CHANGELOG.md) | Riwayat versi |
| [FAQ.md](docs/id/FAQ.md) | Pertanyaan yang sering diajukan |
