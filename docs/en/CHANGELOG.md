# Changelog

All notable changes to QUARR Agent will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Planned
- Web UI dashboard
- Plugin system for custom tools
- Cloud integration (AWS, Azure, GCP security)
- Automated report scheduling

---

## [1.0.0] - 2026-08-30

### 🎉 Initial Release

Complete autonomous cybersecurity agent with 92 tools across 6 security domains.

### Added

#### Core Features
- **Agentic Loop** (M0) — AI-powered autonomous execution
- **Policy Engine** (M1) — Scope-based authorization for all tool calls
- **Finding Validation** (M4) — State machine for finding lifecycle
- **Knowledge Base / RAG** (M5) — OWASP, CWE, MITRE ATT&CK, NIST integration
- **Advanced Agent** (M6) — Phase detection, failure recovery, smart context
- **Reporting** (M7) — Executive, technical reports and JSON export
- **Persistent State** (M9) — Save/load/resume sessions
- **Attack Planner** (M10) — Plan → review → execute workflow
- **Evidence Collection** (M17) — Automatic evidence gathering
- **Retesting** (M18) — Verify remediation

#### Red Team Tools (43)
- **Reconnaissance** (6): target_scope_check, network_discovery, service_enumeration, subdomain_enum, web_fingerprint, waf_detection
- **Discovery** (3): web_content_discovery, web_crawl, parameter_discovery
- **Vulnerability Scanning** (4): vulnerability_scan, web_vuln_scan, ssl_scan, cms_scan
- **Exploitation** (5): sqli_scan, xss_scan, command_injection_scan, bruteforce_login, exploit_search
- **Network Enumeration** (3): smb_enum, dns_enum, snmp_enum
- **Mobile Static** (5): apk_decompile, apk_secrets_scan, apk_manifest_analysis, apk_network_config, apk_cert_check
- **Mobile Dynamic** (6): adb_device_check, adb_app_info, adb_storage_check, adb_logcat_check, frida_ssl_bypass, objection_explore
- **AD Attack** (7): kerberos_asrep_roast, kerberos_kerberoast, secrets_dump, psexec, wmiexec, password_spray, hash_crack
- **AD Enumeration** (4): ldap_search, ldap_domain_dump, bloodhound_collect, rpc_enum

#### Blue Team Tools (19)
- **Defense & Monitoring** (11): firewall_status, firewall_block, firewall_unblock, log_analysis, active_connections, port_audit, process_monitor, service_audit, user_audit, cron_audit, file_integrity_check
- **Threat Hunting** (8): ioc_search, suspicious_files, rootkit_scan, yara_scan, network_capture, dns_anomaly_check, hash_verify, baseline_compare

#### Forensic Tools (16)
- **Digital Forensic** (11): disk_image, file_recovery, memory_dump, memory_analysis, metadata_extract, string_extract, binwalk_analysis, log_timeline, browser_forensic, pcap_analysis, evidence_hash
- **Threat Intel** (5): virustotal_lookup, abuseipdb_check, shodan_lookup, nvd_cve_lookup, threat_feed_check

#### Additional Tools (14)
- **Vulnerability Assessment** (4): cis_benchmark, hardening_check, patch_audit, config_audit
- **SecOps** (5): security_health_check, playbook_execute, metrics_collect, compliance_check, alert_triage

#### LLM Support
- OpenAI API (gpt-4o-mini, gpt-4o, gpt-4-turbo)
- Ollama local models (WhiteRabbitNeo, Llama, CodeLlama)
- Auto-detection and fallback

#### Documentation
- Dual language support (English & Indonesian)
- USAGE.md — Complete guide
- PENTEST_GUIDE.md — Step-by-step workflows
- MOBILE.md — Mobile pentest guide
- BLUE_TEAM_DFIR.md — Defense and forensics guide
- ACTIVE_DIRECTORY.md — AD pentest guide
- API_REFERENCE.md — Full tool reference
- INSTALLATION.md — Setup guide
- ARCHITECTURE.md — System design
- CONTRIBUTING.md — Contribution guide
- FAQ.md — Common questions

---

## Version History

### Milestone Progress

| Milestone | Description | Status |
|-----------|-------------|--------|
| M0 | Basic agent + LLM integration | ✅ Complete |
| M1 | Tool registry + Policy engine | ✅ Complete |
| M2 | Network tools (nmap, subfinder) | ✅ Complete |
| M3 | Web tools (nuclei, sqlmap) | ✅ Complete |
| M4 | Finding validation state machine | ✅ Complete |
| M5 | Knowledge base / RAG | ✅ Complete |
| M6 | Advanced agent (phase, recovery) | ✅ Complete |
| M7 | Reporting & export | ✅ Complete |
| M8 | Mobile pentest tools | ✅ Complete |
| M9 | Persistent state | ✅ Complete |
| M10 | Attack planner | ✅ Complete |
| M11 | Multi-target support | ✅ Complete |
| M12 | Active Directory tools | ✅ Complete |
| M13 | Benchmark framework | ✅ Complete |
| M17 | Evidence collection | ✅ Complete |
| M18 | Retesting engine | ✅ Complete |
| M19 | Blue Team defense tools | ✅ Complete |
| M20 | Threat hunting tools | ✅ Complete |
| M21 | Digital forensic tools | ✅ Complete |

---

## How to Update

```bash
# Update from repository
cd quarr-agent
git pull origin main

# Update dependencies
pip install -r requirements.txt --upgrade

# Verify
python3 -c "from quarr.tools import TOOL_REGISTRY; print(f'{len(TOOL_REGISTRY)} tools')"
```

---

## Reporting Issues

Found a bug or have a feature request?

1. Check existing issues
2. Open new issue with:
   - QUARR version
   - Python version
   - Steps to reproduce
   - Expected vs actual behavior

---

[Unreleased]: https://github.com/your-repo/quarr-agent/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/your-repo/quarr-agent/releases/tag/v1.0.0
