# Testing Guide

QUARR is tested in layered tiers, from fast isolated units up to real tools
against live targets. This guide covers how to run each tier.

## Test tiers

| Tier | What it does | Real tools/network? |
|------|--------------|---------------------|
| **unit** | Detection logic, parsers, validators, scoring | No (mocked) |
| **integration / scenario** | Full agent loop + finding lifecycle with a scripted LLM and patched tool handlers | No (mocked) |
| **live** | Executes the ACTUAL security-tool binaries / APIs end-to-end | Yes (opt-in) |

The default run excludes the live tier (`addopts = -m 'not live'` in
`pyproject.toml`), so CI and a plain `pytest` never touch real tools or the
network.

## Running the default suite

```bash
python3 -m pytest                     # unit + integration (live deselected)
python3 -m pytest --cov=quarr --cov-report=term-missing   # with coverage
```

Coverage is gated at 58% (`fail_under`); the suite currently sits well above it.

## Running the live tiers (opt-in)

Every live harness is gated behind an environment variable and skips cleanly if
unset. **Only point these at systems you own/are authorized to test.**

### Web / network tools (nmap, nuclei, nikto, whatweb, sslscan, masscan)

Spin up a vulnerable lab you control, then opt in:

```bash
docker run -d --rm --name lab -p 8080:80 vulnerables/web-dvwa
export QUARR_LIVE_TARGET=127.0.0.1
export QUARR_LIVE_URL=http://127.0.0.1:8080
python3 -m pytest tests/test_live_tools.py tests/test_live_agent.py -m live -v
docker stop lab
```

A full nuclei scan is slow; the harness runs a bounded template set by default.
Set `QUARR_LIVE_NUCLEI_FULL=1` to run the complete template set.

### Blue-team (read-only inspection of the local host)

```bash
export QUARR_LIVE_BLUE=1
python3 -m pytest tests/test_live_blue_team.py -m live -v
```

State-changing firewall tests are gated behind a second opt-in
(`QUARR_LIVE_BLUE_MUTATE=1`) and only touch RFC 5737 TEST-NET IPs.

### DFIR & threat hunting (read-only inspection of the local host)

```bash
export QUARR_LIVE_DFIR=1
python3 -m pytest tests/test_live_dfir.py -m live -v
```

Exercises real `ps`/`ss`/`find`/`sha256sum`/`file`/log parsing, plus a
chain-of-custody collect → verify → tamper-detect cycle on a temp file.

### Threat intel — NVD CVE lookups (no API key required)

```bash
export QUARR_LIVE_INTEL=1
python3 -m pytest tests/test_live_intel.py -m live -v
```

Hits the public NIST NVD API (keyless). Skips gracefully if NVD throttles
unauthenticated clients. The keyed sources (VirusTotal/AbuseIPDB/Shodan) are
verified only for graceful behaviour without a key — see `SECURITY.md`.

### Active Directory (needs a DC lab such as GOAD)

Deploy a vulnerable AD lab you control — [GOAD](https://github.com/Orange-Cyberdefense/GOAD)
or GOAD-Light — then point the harness at the Domain Controller:

```bash
# Tier 1 — read-only enumeration (ldapsearch / rpcclient / AS-REP roast)
export QUARR_LIVE_AD_DC=10.10.10.10
export QUARR_LIVE_AD_DOMAIN=corp.local
python3 -m pytest tests/test_live_ad.py -m live -v

# Tier 2 — authenticated / intrusive (Kerberoast, DCSync) — second opt-in
export QUARR_LIVE_AD_AUTH=1 QUARR_LIVE_AD_USER=svc_user QUARR_LIVE_AD_PASS='Password123'
python3 -m pytest tests/test_live_ad.py -m live -v
```

Runs the real impacket/ldap binaries end-to-end. Only run against a domain you
are authorized to test.

### Run every live tier at once

```bash
export QUARR_LIVE_TARGET=127.0.0.1 QUARR_LIVE_URL=http://127.0.0.1:8080
export QUARR_LIVE_BLUE=1 QUARR_LIVE_DFIR=1 QUARR_LIVE_INTEL=1
python3 -m pytest -m live -v
```

## Requires external resources (not runnable in a bare environment)

- **VirusTotal / AbuseIPDB / Shodan** live lookups — need free API keys
  (`VIRUSTOTAL_API_KEY`, `ABUSEIPDB_API_KEY`, `SHODAN_API_KEY`). Keyless behaviour
  is tested; live lookups require your own key.
- **Mobile dynamic analysis** — needs a connected Android device/emulator (ADB).
  Static APK analysis is fully tested.

## Linting & formatting

```bash
ruff check quarr/ tests/
black --check quarr/tools/integrations quarr/tools/parsers   # CI-enforced subset
```
