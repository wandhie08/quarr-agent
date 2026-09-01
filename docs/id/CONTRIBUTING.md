# Berkontribusi ke QUARR Agent

Terima kasih atas minat Anda untuk berkontribusi ke QUARR Agent! Dokumen ini memberikan panduan dan instruksi untuk berkontribusi.

---

## Daftar Isi

1. [Kode Etik](#1-kode-etik)
2. [Memulai](#2-memulai)
3. [Setup Development](#3-setup-development)
4. [Struktur Project](#4-struktur-project)
5. [Menambahkan Tool Baru](#5-menambahkan-tool-baru)
6. [Code Style](#6-code-style)
7. [Testing](#7-testing)
8. [Mengirimkan Perubahan](#8-mengirimkan-perubahan)
9. [Panduan Pull Request](#9-panduan-pull-request)
10. [Melaporkan Masalah](#10-melaporkan-masalah)

---

## 1. Kode Etik

- Bersikap hormat dan inklusif
- Fokus pada feedback yang konstruktif
- Bantu menjaga lingkungan yang ramah
- Ikuti prinsip ethical hacking
- Hanya test terhadap sistem yang Anda punya izin untuk test

---

## 2. Memulai

### Prasyarat

- Python 3.10+
- Kali Linux (direkomendasikan) atau Debian/Ubuntu
- Git
- Pemahaman konsep keamanan siber

### Fork dan Clone

```bash
# Fork repository di GitHub

# Clone fork Anda
git clone https://github.com/USERNAME_ANDA/quarr-agent.git
cd quarr-agent

# Tambahkan upstream remote
git remote add upstream https://github.com/original/quarr-agent.git
```

---

## 3. Setup Development

```bash
# Buat virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Install development dependencies
pip install pytest black flake8 mypy

# Copy file environment
cp .env.example .env
# Edit .env dengan API key Anda
```

### Verifikasi Setup

```bash
# Jalankan tests
python3 -m pytest tests/ -v

# Cek tool registry
python3 -c "from quarr.tools import TOOL_REGISTRY; print(f'{len(TOOL_REGISTRY)} tools loaded')"
```

---

## 4. Struktur Project

```
quarr-agent/
├── main.py                 # CLI entrypoint
├── quarr/
│   ├── __init__.py
│   ├── core/
│   │   ├── agent.py        # Core agentic loop
│   │   ├── llm_client.py   # LLM backend (OpenAI/Ollama)
│   │   ├── models.py       # Pydantic data models
│   │   ├── policy.py       # Scope/authorization policy
│   │   ├── validator.py    # Finding validation
│   │   ├── reporter.py     # Report generation
│   │   ├── planner.py      # Attack planner
│   │   ├── persistence.py  # Session save/load
│   │   ├── evidence.py     # Evidence collection
│   │   ├── benchmark.py    # Metrics framework
│   │   └── retest.py       # Retesting engine
│   ├── tools/
│   │   ├── __init__.py     # Tool registry
│   │   ├── registry.py     # Definisi TOOL_REGISTRY
│   │   ├── mobile.py       # Mobile pentest tools
│   │   ├── active_directory.py  # AD tools
│   │   ├── blue_team.py    # Defense tools
│   │   ├── threat_hunting.py    # Hunting tools
│   │   ├── dfir.py         # Forensic tools
│   │   └── ...
│   ├── parsers/
│   │   ├── network.py      # Parser tool network
│   │   └── mobile.py       # Parser tool mobile
│   └── knowledge/
│       └── base.py         # Knowledge base (OWASP, CWE, MITRE)
├── tests/
│   ├── __init__.py
│   └── test_quarr.py
├── docs/
│   ├── en/                 # Dokumentasi English
│   └── id/                 # Dokumentasi Indonesia
└── requirements.txt
```

---

## 5. Menambahkan Tool Baru

### Langkah 1: Definisikan Tool

Tambahkan definisi tool ke file yang sesuai di `quarr/tools/`:

```python
# quarr/tools/your_category.py

def your_tool_handler(params: dict) -> dict:
    """
    Deskripsi tool.
    
    Args:
        params: Dictionary berisi parameter tool
        
    Returns:
        Dictionary dengan hasil tool
    """
    target = params.get("target")
    
    # Implementasi logika tool
    # Biasanya wrap command Kali Linux
    
    import subprocess
    result = subprocess.run(
        ["tool_command", "-arg", target],
        capture_output=True,
        text=True,
        timeout=300
    )
    
    # Parse dan return hasil
    return {
        "target": target,
        "output": result.stdout,
        "status": "success" if result.returncode == 0 else "failed"
    }
```

### Langkah 2: Daftarkan Tool

Tambahkan ke tool registry di `quarr/tools/registry.py`:

```python
TOOL_REGISTRY = {
    # ... tools yang sudah ada ...
    
    "your_tool_name": {
        "name": "your_tool_name",
        "description": "Apa yang tool lakukan - deskriptif untuk LLM",
        "parameters": {
            "target": {
                "type": "string",
                "required": True,
                "description": "Target IP atau hostname"
            },
            "option": {
                "type": "string",
                "required": False,
                "default": "default_value",
                "description": "Parameter opsional"
            }
        },
        "handler": your_tool_handler,
        "kali_tool": "underlying_kali_command",
        "risk_level": "low",  # low, medium, high, critical
        "category": "recon",  # recon, discovery, vuln_scan, exploit, dll.
        "requires_scope": True  # Apakah tool memerlukan target dalam scope
    }
}
```

### Langkah 3: Tambahkan Parser (jika diperlukan)

Jika output tool perlu parsing, tambahkan ke `quarr/parsers/`:

```python
# quarr/parsers/your_parser.py

def parse_your_tool_output(output: str) -> dict:
    """Parse output mentah tool menjadi data terstruktur."""
    results = []
    
    for line in output.split('\n'):
        # Logika parsing
        if relevant_data := extract_data(line):
            results.append(relevant_data)
    
    return {"parsed_results": results}
```

### Langkah 4: Tambahkan Tests

```python
# tests/test_your_tool.py

import pytest
from quarr.tools.your_category import your_tool_handler

def test_your_tool_basic():
    """Test fungsionalitas dasar."""
    result = your_tool_handler({"target": "127.0.0.1"})
    assert result["status"] == "success"

def test_your_tool_invalid_input():
    """Test error handling."""
    result = your_tool_handler({"target": ""})
    assert result["status"] == "failed"
```

### Langkah 5: Update Dokumentasi

Tambahkan dokumentasi tool ke:
- `docs/en/API_REFERENCE.md`
- `docs/id/API_REFERENCE.md`

---

## 6. Code Style

### Python Style

Kami mengikuti PEP 8 dengan beberapa modifikasi:

```bash
# Format code dengan Black
black quarr/ tests/ --line-length 100

# Cek dengan flake8
flake8 quarr/ tests/ --max-line-length 100

# Type checking dengan mypy
mypy quarr/ --ignore-missing-imports
```

### Konvensi Penamaan

| Tipe | Konvensi | Contoh |
|------|----------|--------|
| Functions | snake_case | `parse_nmap_output()` |
| Classes | PascalCase | `ToolRegistry` |
| Constants | UPPER_SNAKE | `MAX_AGENT_STEPS` |
| Tool names | snake_case | `web_content_discovery` |
| File names | snake_case | `active_directory.py` |

### Docstrings

Gunakan Google-style docstrings:

```python
def function_name(param1: str, param2: int = 10) -> dict:
    """
    Deskripsi singkat fungsi.
    
    Deskripsi lebih panjang jika diperlukan.
    
    Args:
        param1: Deskripsi param1
        param2: Deskripsi param2, default 10
        
    Returns:
        Deskripsi return value
        
    Raises:
        ValueError: Ketika param1 kosong
        
    Example:
        >>> result = function_name("test", 5)
        >>> print(result)
    """
    pass
```

---

## 7. Testing

### Jalankan Semua Tests

```bash
python3 -m pytest tests/ -v
```

### Jalankan Test Spesifik

```bash
# Jalankan file test tunggal
python3 -m pytest tests/test_quarr.py -v

# Jalankan test spesifik
python3 -m pytest tests/test_quarr.py::test_function_name -v

# Jalankan dengan coverage
python3 -m pytest tests/ --cov=quarr --cov-report=html
```

### Kategori Test

```bash
# Unit tests saja
python3 -m pytest tests/ -m "unit"

# Integration tests (memerlukan tools terinstall)
python3 -m pytest tests/ -m "integration"
```

### Menulis Tests

```python
import pytest
from quarr.core.models import Finding, FindingStatus

class TestFinding:
    """Tests untuk model Finding."""
    
    def test_finding_creation(self):
        """Test membuat finding baru."""
        finding = Finding(
            id="FIND-001",
            title="SQL Injection",
            severity="high",
            status=FindingStatus.DETECTED
        )
        assert finding.id == "FIND-001"
        assert finding.severity == "high"
    
    @pytest.mark.parametrize("severity,expected", [
        ("critical", 4),
        ("high", 3),
        ("medium", 2),
        ("low", 1),
    ])
    def test_severity_ranking(self, severity, expected):
        """Test ranking severity."""
        finding = Finding(severity=severity)
        assert finding.severity_rank == expected
```

---

## 8. Mengirimkan Perubahan

### Penamaan Branch

```bash
# Feature branch
git checkout -b feature/add-new-tool

# Bug fix branch
git checkout -b fix/parser-error

# Documentation branch
git checkout -b docs/update-readme
```

### Pesan Commit

Ikuti conventional commits:

```
<type>(<scope>): <description>

[optional body]

[optional footer]
```

Types:
- `feat`: Fitur baru
- `fix`: Bug fix
- `docs`: Dokumentasi
- `style`: Code style (formatting)
- `refactor`: Code refactoring
- `test`: Menambahkan tests
- `chore`: Maintenance

Contoh:

```bash
git commit -m "feat(tools): tambah tool SNMP enumeration"
git commit -m "fix(parser): handle output nmap kosong"
git commit -m "docs: update panduan instalasi"
```

### Sebelum Mengirim

```bash
# Update dari upstream
git fetch upstream
git rebase upstream/main

# Jalankan checks
black quarr/ tests/
flake8 quarr/ tests/
python3 -m pytest tests/ -v

# Push ke fork Anda
git push origin feature/your-feature
```

---

## 9. Panduan Pull Request

### PR Checklist

- [ ] Code mengikuti panduan style project
- [ ] Tests ditambahkan untuk fungsionalitas baru
- [ ] Semua tests pass
- [ ] Dokumentasi diupdate
- [ ] Pesan commit mengikuti konvensi
- [ ] Deskripsi PR menjelaskan perubahan

### Template PR

```markdown
## Deskripsi
Deskripsi singkat perubahan.

## Tipe Perubahan
- [ ] Fitur baru
- [ ] Bug fix
- [ ] Update dokumentasi
- [ ] Refactoring

## Testing
Bagaimana ini ditest?

## Checklist
- [ ] Tests pass
- [ ] Dokumentasi diupdate
- [ ] Code diformat dengan Black
```

### Proses Review

1. Submit PR ke branch `main`
2. Automated checks berjalan (CI)
3. Maintainer review code
4. Address feedback jika diperlukan
5. PR di-merge setelah approval

---

## 10. Melaporkan Masalah

### Laporan Bug

Sertakan:
- Versi QUARR
- Versi Python
- Sistem operasi
- Langkah untuk mereproduksi
- Perilaku yang diharapkan
- Perilaku aktual
- Pesan error/logs

### Permintaan Fitur

Sertakan:
- Deskripsi use case
- Solusi yang diusulkan
- Solusi alternatif yang dipertimbangkan
- Konteks tambahan

### Masalah Keamanan

Untuk kerentanan keamanan:
- **JANGAN** buka issue publik
- Email maintainers langsung
- Sertakan deskripsi detail
- Berikan waktu untuk fix sebelum disclosure

---

## Pertanyaan?

- Buka GitHub Discussion untuk pertanyaan
- Bergabung dengan community chat (jika tersedia)
- Cek issue yang sudah ada sebelum membuat yang baru

Terima kasih atas kontribusi Anda! 🎉
