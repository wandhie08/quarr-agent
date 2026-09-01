# Changelog

Semua perubahan penting pada QUARR Agent akan didokumentasikan di file ini.

Format berdasarkan [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
dan project ini mengikuti [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Direncanakan
- Web UI dashboard
- Sistem plugin untuk custom tools
- Integrasi cloud (AWS, Azure, GCP security)
- Penjadwalan report otomatis

---

## [1.0.0] - 2026-08-30

### 🎉 Rilis Awal

Agent keamanan siber otonom lengkap dengan 92 tools di 6 domain keamanan.

### Ditambahkan

#### Fitur Inti
- **Agentic Loop** (M0) — Eksekusi otonom berbasis AI
- **Policy Engine** (M1) — Otorisasi berbasis scope untuk semua tool calls
- **Finding Validation** (M4) — State machine untuk lifecycle finding
- **Knowledge Base / RAG** (M5) — Integrasi OWASP, CWE, MITRE ATT&CK, NIST
- **Advanced Agent** (M6) — Deteksi fase, recovery dari kegagalan, smart context
- **Reporting** (M7) — Report executive, teknis dan export JSON
- **Persistent State** (M9) — Save/load/resume sessions
- **Attack Planner** (M10) — Workflow plan → review → execute
- **Evidence Collection** (M17) — Pengumpulan evidence otomatis
- **Retesting** (M18) — Verifikasi remediasi

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

#### Tools Tambahan (14)
- **Vulnerability Assessment** (4): cis_benchmark, hardening_check, patch_audit, config_audit
- **SecOps** (5): security_health_check, playbook_execute, metrics_collect, compliance_check, alert_triage

#### Dukungan LLM
- OpenAI API (gpt-4o-mini, gpt-4o, gpt-4-turbo)
- Ollama model lokal (WhiteRabbitNeo, Llama, CodeLlama)
- Auto-detection dan fallback

#### Dokumentasi
- Dukungan dual bahasa (English & Indonesia)
- USAGE.md — Panduan lengkap
- PENTEST_GUIDE.md — Workflow step-by-step
- MOBILE.md — Panduan mobile pentest
- BLUE_TEAM_DFIR.md — Panduan defense dan forensics
- ACTIVE_DIRECTORY.md — Panduan AD pentest
- API_REFERENCE.md — Referensi lengkap tool
- INSTALLATION.md — Panduan setup
- ARCHITECTURE.md — Desain sistem
- CONTRIBUTING.md — Panduan kontribusi
- FAQ.md — Pertanyaan umum

---

## Riwayat Versi

### Progress Milestone

| Milestone | Deskripsi | Status |
|-----------|-----------|--------|
| M0 | Agent dasar + integrasi LLM | ✅ Selesai |
| M1 | Tool registry + Policy engine | ✅ Selesai |
| M2 | Network tools (nmap, subfinder) | ✅ Selesai |
| M3 | Web tools (nuclei, sqlmap) | ✅ Selesai |
| M4 | Finding validation state machine | ✅ Selesai |
| M5 | Knowledge base / RAG | ✅ Selesai |
| M6 | Advanced agent (fase, recovery) | ✅ Selesai |
| M7 | Reporting & export | ✅ Selesai |
| M8 | Mobile pentest tools | ✅ Selesai |
| M9 | Persistent state | ✅ Selesai |
| M10 | Attack planner | ✅ Selesai |
| M11 | Multi-target support | ✅ Selesai |
| M12 | Active Directory tools | ✅ Selesai |
| M13 | Benchmark framework | ✅ Selesai |
| M17 | Evidence collection | ✅ Selesai |
| M18 | Retesting engine | ✅ Selesai |
| M19 | Blue Team defense tools | ✅ Selesai |
| M20 | Threat hunting tools | ✅ Selesai |
| M21 | Digital forensic tools | ✅ Selesai |

---

## Cara Update

```bash
# Update dari repository
cd quarr-agent
git pull origin main

# Update dependencies
pip install -r requirements.txt --upgrade

# Verifikasi
python3 -c "from quarr.tools import TOOL_REGISTRY; print(f'{len(TOOL_REGISTRY)} tools')"
```

---

## Melaporkan Masalah

Menemukan bug atau punya permintaan fitur?

1. Cek issue yang sudah ada
2. Buka issue baru dengan:
   - Versi QUARR
   - Versi Python
   - Langkah untuk mereproduksi
   - Perilaku yang diharapkan vs aktual

---

[Unreleased]: https://github.com/your-repo/quarr-agent/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/your-repo/quarr-agent/releases/tag/v1.0.0
