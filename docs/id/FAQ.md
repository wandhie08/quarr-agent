# FAQ — QUARR Agent

Pertanyaan yang Sering Diajukan tentang QUARR Agent.

---

## Daftar Isi

1. [Umum](#1-umum)
2. [Instalasi](#2-instalasi)
3. [Konfigurasi](#3-konfigurasi)
4. [Penggunaan](#4-penggunaan)
5. [Tools](#5-tools)
6. [LLM / AI](#6-llm--ai)
7. [Troubleshooting](#7-troubleshooting)
8. [Keamanan & Etika](#8-keamanan--etika)

---

## 1. Umum

### Apa itu QUARR Agent?

QUARR (Query-driven Unified Autonomous Red/Blue Research) Agent adalah tool keamanan siber berbasis AI yang mengotomatisasi penetration testing, blue team defense, dan digital forensics. Menggunakan LLM (Large Language Models) untuk mengorkestrasi 92 security tools secara cerdas.

### Apa yang bisa dilakukan QUARR?

- **Red Team (43 tools)**: Pentest web, network, mobile, dan Active Directory
- **Blue Team (19 tools)**: Defense, monitoring, threat hunting
- **Forensics (16 tools)**: Incident response, analisis memory/disk, pengumpulan evidence
- **Threat Intel (5 tools)**: Integrasi VirusTotal, Shodan, AbuseIPDB
- **Vulnerability Assessment (4 tools)**: CIS benchmarks, hardening checks
- **SecOps (5 tools)**: Health checks, compliance, playbooks

### Apakah QUARR gratis?

QUARR Agent sendiri open source. Namun:
- **OpenAI API** memerlukan API key berbayar
- **Ollama** gratis tapi memerlukan resource komputasi lokal

### Sistem operasi apa yang didukung?

- **Direkomendasikan**: Kali Linux (semua tools sudah terinstall)
- **Didukung**: Debian, Ubuntu (perlu install tools Kali)
- **Tidak didukung**: Windows, macOS (tools spesifik Linux)

---

## 2. Instalasi

### Apa kebutuhan minimum?

| Komponen | Minimum | Direkomendasikan |
|----------|---------|------------------|
| RAM | 8 GB | 16 GB |
| Disk | 10 GB | 50 GB |
| Python | 3.10 | 3.11+ |
| OS | Kali Linux | Kali Linux (terbaru) |

### Bagaimana cara install QUARR?

```bash
git clone https://github.com/your-repo/quarr-agent.git
cd quarr-agent
pip install -r requirements.txt
cp .env.example .env
# Edit .env dengan API key Anda
python3 main.py
```

Lihat [INSTALLATION.md](INSTALLATION.md) untuk instruksi detail.

### Apakah saya perlu install semua 92 tools?

Tidak. QUARR menangani tools yang hilang dengan baik:
- Agent akan skip tools yang tidak tersedia
- Fungsionalitas inti bekerja dengan tools dasar (nmap, nuclei, sqlmap)
- Install tools sesuai kebutuhan use case Anda

### Bagaimana cara install tools yang hilang?

```bash
# Kebanyakan tools ada di repo Kali
sudo apt install <nama-tool>

# Python tools
pip install <package>

# Cek ketersediaan tool
which <nama-tool>
```

---

## 3. Konfigurasi

### Bagaimana cara mengkonfigurasi OpenAI?

Edit `.env`:

```bash
OPENAI_API_KEY=sk-proj-your-key-here
OPENAI_MODEL=gpt-4o-mini
```

### Bagaimana cara menggunakan Ollama?

1. Install Ollama: `curl -fsSL https://ollama.com/install.sh | sh`
2. Pull model: `ollama pull WhiteRabbitNeo/WhiteRabbitNeo-2.5-Qwen-2.5-Coder-7B`
3. Kosongkan `OPENAI_API_KEY` di `.env`

### Model LLM mana yang terbaik?

| Use Case | Model Direkomendasikan |
|----------|------------------------|
| Penggunaan umum | gpt-4o-mini (cepat, murah) |
| Tugas kompleks | gpt-4o (akurat) |
| Offline/Privasi | WhiteRabbitNeo (lokal) |
| Resource rendah | Llama 3.1 8B (lokal) |

### Bagaimana cara mengubah max agent steps?

Edit `quarr/core/agent.py`:

```python
MAX_AGENT_STEPS = 20  # Default adalah 15
```

---

## 4. Penggunaan

### Bagaimana cara memulai pentest?

```
🔐 quarr> Full pentest on target.com
```

Agent otomatis menjalankan reconnaissance, discovery, vulnerability scanning, dan exploitation.

### Bagaimana cara membatasi scope?

Saat setup engagement:

```
Assessment name: My Pentest
  + target: target.com
  + target: 10.10.10.0/24
  - exclude: 10.10.10.1
```

### Bagaimana cara menyimpan dan melanjutkan session?

```
🔐 quarr> save          # Simpan session saat ini
🔐 quarr> quit          # Auto-save saat keluar

# Kali berikutnya:
🔐 quarr> load          # List session tersimpan
Load session #: 1       # Lanjutkan session
```

### Bagaimana cara generate report?

```
🔐 quarr> report        # Ringkasan executive (terminal)
🔐 quarr> executive     # Export report executive (markdown)
🔐 quarr> technical     # Export report teknis (markdown)
🔐 quarr> export        # Export findings (JSON)
```

### Bagaimana cara merencanakan sebelum eksekusi?

```
🔐 quarr> plan Web pentest target.com
# Review plan
Approve plan? (y/n): y
# Agent mengeksekusi plan
```

---

## 5. Tools

### Kenapa tool gagal?

Alasan umum:
1. **Tool tidak terinstall**: `apt install <tool>`
2. **Dependencies hilang**: Cek dokumentasi tool
3. **Permission denied**: Jalankan dengan sudo atau perbaiki permission
4. **Target tidak reachable**: Cek konektivitas jaringan
5. **Rate limited**: Tunggu dan coba lagi

### Bagaimana cara menjalankan tool spesifik?

Minta agent langsung:

```
🔐 quarr> Jalankan nmap scan di 192.168.1.1
🔐 quarr> SQL injection test di https://target.com/page?id=1
🔐 quarr> Cek status firewall
```

### Bisakah saya menambahkan custom tools?

Ya! Lihat [CONTRIBUTING.md](CONTRIBUTING.md) untuk instruksi menambahkan tools baru.

### Tools apa yang memerlukan root/sudo?

| Kategori Tool | Perlu Root |
|---------------|------------|
| Network capture | Ya |
| Memory dump | Ya |
| Disk imaging | Ya |
| Manajemen firewall | Ya |
| ADB (beberapa operasi) | Ya |
| Kebanyakan tools lain | Tidak |

---

## 6. LLM / AI

### Bagaimana AI bekerja?

1. User memberikan query
2. Agent membangun context (scope, state, knowledge)
3. LLM memutuskan tool mana yang dijalankan
4. Tool dieksekusi dan mengembalikan hasil
5. Agent update state dan validasi findings
6. Loop berlanjut sampai tugas selesai

### Apakah data saya dikirim ke OpenAI?

Jika menggunakan OpenAI:
- Query dan output tool Anda dikirim ke OpenAI API
- Kebijakan retensi data OpenAI berlaku
- Untuk engagement sensitif, gunakan Ollama (sepenuhnya lokal)

### Kenapa agent kadang membuat kesalahan?

LLM bersifat probabilistik. Masalah umum:
- **Halusinasi**: LLM menciptakan tools yang tidak ada
- **Parameter salah**: Salah interpretasi syntax tool
- **Loop**: Terjebak mengulangi aksi yang sama

Solusi:
- Gunakan model yang lebih baik (gpt-4o vs gpt-4o-mini)
- Berikan instruksi yang lebih jelas
- Laporkan masalah untuk perbaikan

### Bagaimana cara meningkatkan akurasi?

1. Spesifik dalam query Anda
2. Berikan context (info target, batasan)
3. Gunakan perintah `plan` untuk review sebelum eksekusi
4. Upgrade ke model yang lebih capable

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

Cek:
1. API key benar di `.env`
2. Anda punya kredit API
3. Konektivitas internet

### "Ollama connection refused"

```bash
# Start Ollama server
ollama serve

# Cek apakah berjalan
curl http://localhost:11434/api/tags
```

### "Permission denied"

```bash
# Untuk network tools
sudo python3 main.py

# Atau perbaiki permission spesifik
sudo chmod +x /path/to/tool
```

### Agent terjebak dalam loop

1. Tekan Ctrl+C untuk interrupt
2. Coba rephrase query Anda
3. Gunakan perintah `plan` untuk tugas kompleks
4. Cek apakah tool mengembalikan error

### Session tidak tersimpan

1. Cek write permission ke direktori `engagements/`
2. Pastikan disk space tersedia
3. Cek JSON errors di state file

### Tool timeout

Beberapa tools memakan waktu lama. Opsi:
1. Tunggu sampai selesai
2. Gunakan scan profile yang lebih cepat
3. Kurangi scope

---

## 8. Keamanan & Etika

### Apakah QUARR legal digunakan?

QUARR adalah tool. Penggunaan legal tergantung pada:
- **Anda HARUS memiliki otorisasi** untuk test sistem target
- Testing tanpa izin ilegal di kebanyakan yurisdiksi
- Selalu dapatkan izin tertulis sebelum pentesting

### Bagaimana cara menggunakan QUARR secara etis?

1. **Hanya test sistem yang Anda miliki atau punya izin untuk test**
2. Hormati batasan scope
3. Laporkan findings secara bertanggung jawab
4. Jangan gunakan untuk tujuan jahat
5. Ikuti kebijakan organisasi Anda

### Bagaimana dengan responsible disclosure?

Jika Anda menemukan kerentanan:
1. Dokumentasikan findings dengan jelas
2. Laporkan ke pemilik sistem
3. Berikan waktu yang wajar untuk fix
4. Jangan eksploitasi atau ungkapkan secara publik

### Apakah QUARR menyimpan credentials?

- API key disimpan di `.env` (file lokal)
- Credentials yang didapat dari pentesting disimpan di session state
- Lindungi direktori `engagements/` Anda
- Jangan commit `.env` atau sessions ke git

### Bisakah QUARR digunakan untuk tujuan jahat?

QUARR dirancang untuk security testing yang sah. Penyalahgunaan untuk:
- Akses tanpa izin
- Pencurian data
- Kerusakan sistem
- Aktivitas ilegal apapun

Sangat dilarang dan mungkin ilegal.

---

## Masih Punya Pertanyaan?

- Cek [Dokumentasi](README.md)
- Buka GitHub Issue
- Bergabung dengan diskusi komunitas

---

*Terakhir diupdate: Agustus 2026*
