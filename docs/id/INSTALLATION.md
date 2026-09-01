# Panduan Instalasi — QUARR Agent

Panduan lengkap untuk menginstall dan mengkonfigurasi QUARR Agent di Kali Linux.

---

## Daftar Isi

1. [Kebutuhan Sistem](#1-kebutuhan-sistem)
2. [Instalasi Cepat](#2-instalasi-cepat)
3. [Setup LLM Backend](#3-setup-llm-backend)
4. [Tools Kali Linux](#4-tools-kali-linux)
5. [Tools Mobile Pentest](#5-tools-mobile-pentest)
6. [Tools Active Directory](#6-tools-active-directory)
7. [Tools Blue Team & Forensic](#7-tools-blue-team--forensic)
8. [Verifikasi](#8-verifikasi)
9. [Instalasi Docker (Opsional)](#9-instalasi-docker-opsional)
10. [Update](#10-update)

---

## 1. Kebutuhan Sistem

### Minimum

| Komponen | Kebutuhan |
|----------|-----------|
| OS | Kali Linux 2023.x+ (atau Debian/Ubuntu dengan repo Kali) |
| Python | 3.10+ |
| RAM | 8 GB (16 GB direkomendasikan untuk Ollama) |
| Disk | 10 GB kosong (50 GB jika menggunakan model Ollama) |
| Network | Akses internet untuk OpenAI API |

### Direkomendasikan

- Kali Linux (full installation)
- 16 GB RAM
- SSD storage
- Akses root/sudo

---

## 2. Instalasi Cepat

```bash
# Clone repository
git clone https://github.com/your-repo/quarr-agent.git
cd quarr-agent

# Buat virtual environment (direkomendasikan)
python3 -m venv venv
source venv/bin/activate

# Install dependensi Python
pip install -r requirements.txt

# Konfigurasi environment
cp .env.example .env
nano .env  # Tambahkan API key

# Jalankan
python3 main.py
```

---

## 3. Setup LLM Backend

QUARR mendukung dua backend LLM. Pilih salah satu:

### Opsi A: OpenAI (Direkomendasikan)

Tercepat dan paling akurat. Butuh API key dan internet.

```bash
# Edit .env
OPENAI_API_KEY=sk-proj-your-api-key-here
OPENAI_MODEL=gpt-4o-mini
```

Model yang tersedia:
| Model | Kecepatan | Akurasi | Biaya |
|-------|-----------|---------|-------|
| gpt-4o-mini | Cepat | Bagus | Murah |
| gpt-4o | Sedang | Sangat Bagus | Sedang |
| gpt-4-turbo | Lambat | Sangat Bagus | Mahal |

Dapatkan API key: https://platform.openai.com/api-keys

### Opsi B: Ollama (Offline/Lokal)

Berjalan sepenuhnya offline. Butuh resource lebih.

```bash
# Install Ollama
curl -fsSL https://ollama.com/install.sh | sh

# Pull model yang fokus security
ollama pull WhiteRabbitNeo/WhiteRabbitNeo-2.5-Qwen-2.5-Coder-7B

# Atau gunakan model lain
ollama pull llama3.1:8b
ollama pull codellama:13b

# Verifikasi Ollama berjalan
ollama list
```

Konfigurasi `.env` untuk Ollama:
```bash
# Kosongkan OPENAI_API_KEY untuk menggunakan Ollama
OPENAI_API_KEY=
OLLAMA_MODEL=WhiteRabbitNeo/WhiteRabbitNeo-2.5-Qwen-2.5-Coder-7B:latest
```

Paksa Ollama meskipun ada OpenAI key:
```bash
OPENAI_API_KEY="" python3 main.py
```

---

## 4. Tools Kali Linux

### Tools Inti (Wajib)

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
pip install dalfox  # atau: sudo apt install dalfox
sudo apt install -y commix

# Network enumeration
sudo apt install -y enum4linux dnsenum snmp

# Exploit database
sudo apt install -y exploitdb
```

### Verifikasi Tools Inti

```bash
# Cek semua tools
for tool in nmap whatweb wafw00f subfinder gobuster katana nuclei nikto sslscan wpscan sqlmap hydra enum4linux dnsenum; do
    which $tool && echo "✅ $tool OK" || echo "❌ $tool TIDAK ADA"
done
```

---

## 5. Tools Mobile Pentest

### Static Analysis (APK tanpa device)

```bash
# APK decompilation
sudo apt install -y apktool jadx

# Certificate analysis
sudo apt install -y apksigner
# keytool sudah ada di Java (default-jdk)
sudo apt install -y default-jdk
```

### Dynamic Analysis (butuh device/emulator)

```bash
# Android Debug Bridge
sudo apt install -y adb

# Frida (runtime instrumentation)
pip install frida-tools

# Objection (mobile exploration)
pip install objection
```

### Setup Device untuk Dynamic Analysis

```bash
# Cek device yang terhubung
adb devices

# Untuk device yang sudah root dengan Frida:
# 1. Download frida-server sesuai arsitektur device
# https://github.com/frida/frida/releases

# 2. Push ke device
adb push frida-server-android-arm64 /data/local/tmp/frida-server
adb shell "chmod +x /data/local/tmp/frida-server"

# 3. Jalankan frida-server (sebagai root)
adb shell "su -c '/data/local/tmp/frida-server &'"

# 4. Verifikasi
frida-ps -U
```

---

## 6. Tools Active Directory

### Impacket Suite

```bash
# Install Impacket
sudo apt install -y python3-impacket

# Atau via pip (versi terbaru)
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

# BloodHound GUI (opsional, untuk visualisasi)
sudo apt install -y bloodhound
```

### Password Cracking

```bash
# Hashcat
sudo apt install -y hashcat

# John the Ripper
sudo apt install -y john
```

### Verifikasi Tools AD

```bash
# Cek Impacket
python3 -c "from impacket import version; print(f'Impacket {version.VER_MINOR}')"

# Cek CrackMapExec
crackmapexec --version

# Cek BloodHound Python
bloodhound-python --help
```

---

## 7. Tools Blue Team & Forensic

### Defense & Monitoring

```bash
# Firewall (biasanya sudah terinstall)
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

### Verifikasi Tools Forensic

```bash
# Cek Volatility 3
vol --help

# Cek disk tools
which dcfldd foremost

# Cek analysis tools
which exiftool binwalk tshark
```

---

## 8. Verifikasi

### Cek Sistem Lengkap

```bash
cd quarr-agent

# Cek dependensi Python
pip check

# Cek tool registry
python3 -c "from quarr.tools import TOOL_REGISTRY; print(f'{len(TOOL_REGISTRY)} tools loaded')"

# Jalankan test
python3 -m pytest tests/ -v

# Start agent
python3 main.py
```

### Output yang Diharapkan

```
🤖 Backend: OpenAI
   Model: gpt-4o-mini

📋 ENGAGEMENT SETUP
Assessment name: 
```

Jika muncul seperti ini, instalasi berhasil!

---

## 9. Instalasi Docker (Opsional)

Untuk environment yang terisolasi:

```bash
# Build image
docker build -t quarr-agent .

# Jalankan dengan file .env
docker run -it --rm \
    -v $(pwd)/.env:/app/.env \
    -v $(pwd)/engagements:/app/engagements \
    --network host \
    quarr-agent
```

### Contoh Dockerfile

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

## 10. Update

### Update QUARR Agent

```bash
cd quarr-agent
git pull origin main
pip install -r requirements.txt --upgrade
```

### Update Tools Kali

```bash
sudo apt update && sudo apt upgrade -y
```

### Update Model Ollama

```bash
ollama pull WhiteRabbitNeo/WhiteRabbitNeo-2.5-Qwen-2.5-Coder-7B
```

### Update Template Nuclei

```bash
nuclei -ut
```

---

## Troubleshooting

| Masalah | Solusi |
|---------|--------|
| `ModuleNotFoundError` | Jalankan `pip install -r requirements.txt` |
| `command not found: nmap` | Install: `sudo apt install nmap` |
| OpenAI API error | Cek API key di `.env` |
| Ollama connection refused | Start Ollama: `ollama serve` |
| Permission denied | Jalankan dengan `sudo` atau perbaiki permission |
| Frida tidak konek | Cek frida-server berjalan di device |

Untuk bantuan lebih lanjut, lihat [FAQ.md](FAQ.md) atau buka issue.
