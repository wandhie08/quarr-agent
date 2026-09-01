# Installation Guide — QUARR Agent

Complete guide to install and configure QUARR Agent on Kali Linux.

---

## Table of Contents

1. [System Requirements](#1-system-requirements)
2. [Quick Installation](#2-quick-installation)
3. [LLM Backend Setup](#3-llm-backend-setup)
4. [Kali Linux Tools](#4-kali-linux-tools)
5. [Mobile Pentest Tools](#5-mobile-pentest-tools)
6. [Active Directory Tools](#6-active-directory-tools)
7. [Blue Team & Forensic Tools](#7-blue-team--forensic-tools)
8. [Verification](#8-verification)
9. [Docker Installation (Optional)](#9-docker-installation-optional)
10. [Updating](#10-updating)

---

## 1. System Requirements

### Minimum

| Component | Requirement |
|-----------|-------------|
| OS | Kali Linux 2023.x+ (or Debian/Ubuntu with Kali repos) |
| Python | 3.10+ |
| RAM | 8 GB (16 GB recommended for Ollama) |
| Disk | 10 GB free (50 GB if using Ollama models) |
| Network | Internet access for OpenAI API |

### Recommended

- Kali Linux (full installation)
- 16 GB RAM
- SSD storage
- Root/sudo access

---

## 2. Quick Installation

```bash
# Clone repository
git clone https://github.com/your-repo/quarr-agent.git
cd quarr-agent

# Create virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate

# Install Python dependencies
pip install -r requirements.txt

# Configure environment
cp .env.example .env
nano .env  # Add your API key

# Run
python3 main.py
```

---

## 3. LLM Backend Setup

QUARR supports two LLM backends. Choose one:

### Option A: OpenAI (Recommended)

Fastest and most accurate. Requires API key and internet.

```bash
# Edit .env
OPENAI_API_KEY=sk-proj-your-api-key-here
OPENAI_MODEL=gpt-4o-mini
```

Available models:
| Model | Speed | Accuracy | Cost |
|-------|-------|----------|------|
| gpt-4o-mini | Fast | Good | Low |
| gpt-4o | Medium | Excellent | Medium |
| gpt-4-turbo | Slow | Excellent | High |

Get API key: https://platform.openai.com/api-keys

### Option B: Ollama (Offline/Local)

Run completely offline. Requires more resources.

```bash
# Install Ollama
curl -fsSL https://ollama.com/install.sh | sh

# Pull security-focused model
ollama pull WhiteRabbitNeo/WhiteRabbitNeo-2.5-Qwen-2.5-Coder-7B

# Or use other models
ollama pull llama3.1:8b
ollama pull codellama:13b

# Verify Ollama is running
ollama list
```

Configure `.env` for Ollama:
```bash
# Leave OPENAI_API_KEY empty to use Ollama
OPENAI_API_KEY=
OLLAMA_MODEL=WhiteRabbitNeo/WhiteRabbitNeo-2.5-Qwen-2.5-Coder-7B:latest
```

Force Ollama even if OpenAI key exists:
```bash
OPENAI_API_KEY="" python3 main.py
```

---

## 4. Kali Linux Tools

### Core Tools (Required)

```bash
# Update package list
sudo apt update

# Network reconnaissance
sudo apt install -y nmap whatweb wafw00f

# Subdomain enumeration
sudo apt install -y subfinder amass

# Web content discovery
sudo apt install -y gobuster dirb

# Web crawling
sudo apt install -y katana

# Parameter discovery
pip install arjun

# Vulnerability scanning
sudo apt install -y nuclei nikto sslscan

# CMS scanning
sudo apt install -y wpscan

# Exploitation tools
sudo apt install -y sqlmap hydra
pip install dalfox  # or: sudo apt install dalfox
sudo apt install -y commix

# Network enumeration
sudo apt install -y enum4linux dnsenum snmp

# Exploit database
sudo apt install -y exploitdb
```

### Verify Core Tools

```bash
# Check all tools
for tool in nmap whatweb wafw00f subfinder gobuster katana nuclei nikto sslscan wpscan sqlmap hydra enum4linux dnsenum; do
    which $tool && echo "✅ $tool OK" || echo "❌ $tool MISSING"
done
```

---

## 5. Mobile Pentest Tools

### Static Analysis (APK without device)

```bash
# APK decompilation
sudo apt install -y apktool jadx

# Certificate analysis
sudo apt install -y apksigner
# keytool comes with Java (default-jdk)
sudo apt install -y default-jdk
```

### Dynamic Analysis (requires device/emulator)

```bash
# Android Debug Bridge
sudo apt install -y adb

# Frida (runtime instrumentation)
pip install frida-tools

# Objection (mobile exploration)
pip install objection
```

### Device Setup for Dynamic Analysis

```bash
# Check connected device
adb devices

# For rooted device with Frida:
# 1. Download frida-server for your device architecture
# https://github.com/frida/frida/releases

# 2. Push to device
adb push frida-server-android-arm64 /data/local/tmp/frida-server
adb shell "chmod +x /data/local/tmp/frida-server"

# 3. Run frida-server (as root)
adb shell "su -c '/data/local/tmp/frida-server &'"

# 4. Verify
frida-ps -U
```

---

## 6. Active Directory Tools

### Impacket Suite

```bash
# Install Impacket
sudo apt install -y python3-impacket

# Or via pip (latest version)
pip install impacket
```

### AD Enumeration

```bash
# CrackMapExec
sudo apt install -y crackmapexec

# LDAP tools
sudo apt install -y ldap-utils
pip install ldapdomaindump

# BloodHound
pip install bloodhound

# BloodHound GUI (optional, for visualization)
sudo apt install -y bloodhound
```

### Password Cracking

```bash
# Hashcat
sudo apt install -y hashcat

# John the Ripper
sudo apt install -y john
```

### Verify AD Tools

```bash
# Check Impacket
python3 -c "from impacket import version; print(f'Impacket {version.VER_MINOR}')"

# Check CrackMapExec
crackmapexec --version

# Check BloodHound Python
bloodhound-python --help
```

---

## 7. Blue Team & Forensic Tools

### Defense & Monitoring

```bash
# Firewall (usually pre-installed)
sudo apt install -y iptables ufw

# Rootkit detection
sudo apt install -y chkrootkit rkhunter

# YARA
sudo apt install -y yara

# Network capture
sudo apt install -y tcpdump wireshark-cli
```

### Digital Forensics

```bash
# Memory forensics
pip install volatility3

# Disk imaging
sudo apt install -y dcfldd

# File recovery
sudo apt install -y foremost scalpel

# Metadata extraction
sudo apt install -y exiftool

# Binary analysis
sudo apt install -y binwalk strings

# Network forensics
sudo apt install -y tshark
```

### Verify Forensic Tools

```bash
# Check Volatility 3
vol --help

# Check disk tools
which dcfldd foremost

# Check analysis tools
which exiftool binwalk tshark
```

---

## 8. Verification

### Full System Check

```bash
cd quarr-agent

# Check Python dependencies
pip check

# Check tool registry
python3 -c "from quarr.tools import TOOL_REGISTRY; print(f'{len(TOOL_REGISTRY)} tools loaded')"

# Run test
python3 -m pytest tests/ -v

# Start agent
python3 main.py
```

### Expected Output

```
🤖 Backend: OpenAI
   Model: gpt-4o-mini

📋 ENGAGEMENT SETUP
Assessment name: 
```

If you see this, installation is successful!

---

## 9. Docker Installation (Optional)

For isolated environment:

```bash
# Build image
docker build -t quarr-agent .

# Run with .env file
docker run -it --rm \
    -v $(pwd)/.env:/app/.env \
    -v $(pwd)/engagements:/app/engagements \
    --network host \
    quarr-agent
```

### Dockerfile Example

```dockerfile
FROM kalilinux/kali-rolling

RUN apt update && apt install -y \
    python3 python3-pip \
    nmap whatweb wafw00f subfinder gobuster \
    nuclei nikto sslscan wpscan sqlmap hydra \
    enum4linux dnsenum \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .

CMD ["python3", "main.py"]
```

---

## 10. Updating

### Update QUARR Agent

```bash
cd quarr-agent
git pull origin main
pip install -r requirements.txt --upgrade
```

### Update Kali Tools

```bash
sudo apt update && sudo apt upgrade -y
```

### Update Ollama Models

```bash
ollama pull WhiteRabbitNeo/WhiteRabbitNeo-2.5-Qwen-2.5-Coder-7B
```

### Update Nuclei Templates

```bash
nuclei -ut
```

---

## Troubleshooting

| Issue | Solution |
|-------|----------|
| `ModuleNotFoundError` | Run `pip install -r requirements.txt` |
| `command not found: nmap` | Install: `sudo apt install nmap` |
| OpenAI API error | Check API key in `.env` |
| Ollama connection refused | Start Ollama: `ollama serve` |
| Permission denied | Run with `sudo` or fix permissions |
| Frida not connecting | Check frida-server running on device |

For more help, see [FAQ.md](FAQ.md) or open an issue.
