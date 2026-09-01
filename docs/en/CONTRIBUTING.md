# Contributing to QUARR Agent

Thank you for your interest in contributing to QUARR Agent! This document provides guidelines and instructions for contributing.

---

## Table of Contents

1. [Code of Conduct](#1-code-of-conduct)
2. [Getting Started](#2-getting-started)
3. [Development Setup](#3-development-setup)
4. [Project Structure](#4-project-structure)
5. [Adding New Tools](#5-adding-new-tools)
6. [Code Style](#6-code-style)
7. [Testing](#7-testing)
8. [Submitting Changes](#8-submitting-changes)
9. [Pull Request Guidelines](#9-pull-request-guidelines)
10. [Reporting Issues](#10-reporting-issues)

---

## 1. Code of Conduct

- Be respectful and inclusive
- Focus on constructive feedback
- Help maintain a welcoming environment
- Follow ethical hacking principles
- Only test against systems you have permission to test

---

## 2. Getting Started

### Prerequisites

- Python 3.10+
- Kali Linux (recommended) or Debian/Ubuntu
- Git
- Understanding of cybersecurity concepts

### Fork and Clone

```bash
# Fork the repository on GitHub

# Clone your fork
git clone https://github.com/YOUR_USERNAME/quarr-agent.git
cd quarr-agent

# Add upstream remote
git remote add upstream https://github.com/original/quarr-agent.git
```

---

## 3. Development Setup

```bash
# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Install development dependencies
pip install pytest black flake8 mypy

# Copy environment file
cp .env.example .env
# Edit .env with your API keys
```

### Verify Setup

```bash
# Run tests
python3 -m pytest tests/ -v

# Check tool registry
python3 -c "from quarr.tools import TOOL_REGISTRY; print(f'{len(TOOL_REGISTRY)} tools loaded')"
```

---

## 4. Project Structure

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
│   │   ├── registry.py     # TOOL_REGISTRY definition
│   │   ├── mobile.py       # Mobile pentest tools
│   │   ├── active_directory.py  # AD tools
│   │   ├── blue_team.py    # Defense tools
│   │   ├── threat_hunting.py    # Hunting tools
│   │   ├── dfir.py         # Forensic tools
│   │   └── ...
│   ├── parsers/
│   │   ├── network.py      # Network tool parsers
│   │   └── mobile.py       # Mobile tool parsers
│   └── knowledge/
│       └── base.py         # Knowledge base (OWASP, CWE, MITRE)
├── tests/
│   ├── __init__.py
│   └── test_quarr.py
├── docs/
│   ├── en/                 # English documentation
│   └── id/                 # Indonesian documentation
└── requirements.txt
```

---

## 5. Adding New Tools

### Step 1: Define the Tool

Add tool definition to the appropriate file in `quarr/tools/`:

```python
# quarr/tools/your_category.py

def your_tool_handler(params: dict) -> dict:
    """
    Tool description.
    
    Args:
        params: Dictionary containing tool parameters
        
    Returns:
        Dictionary with tool results
    """
    target = params.get("target")
    
    # Implement tool logic
    # Usually wraps a Kali Linux command
    
    import subprocess
    result = subprocess.run(
        ["tool_command", "-arg", target],
        capture_output=True,
        text=True,
        timeout=300
    )
    
    # Parse and return results
    return {
        "target": target,
        "output": result.stdout,
        "status": "success" if result.returncode == 0 else "failed"
    }
```

### Step 2: Register the Tool

Add to the tool registry in `quarr/tools/registry.py`:

```python
TOOL_REGISTRY = {
    # ... existing tools ...
    
    "your_tool_name": {
        "name": "your_tool_name",
        "description": "What the tool does - be descriptive for the LLM",
        "parameters": {
            "target": {
                "type": "string",
                "required": True,
                "description": "Target IP or hostname"
            },
            "option": {
                "type": "string",
                "required": False,
                "default": "default_value",
                "description": "Optional parameter"
            }
        },
        "handler": your_tool_handler,
        "kali_tool": "underlying_kali_command",
        "risk_level": "low",  # low, medium, high, critical
        "category": "recon",  # recon, discovery, vuln_scan, exploit, etc.
        "requires_scope": True  # Whether tool requires target in scope
    }
}
```

### Step 3: Add Parser (if needed)

If the tool output needs parsing, add to `quarr/parsers/`:

```python
# quarr/parsers/your_parser.py

def parse_your_tool_output(output: str) -> dict:
    """Parse raw tool output into structured data."""
    results = []
    
    for line in output.split('\n'):
        # Parse logic
        if relevant_data := extract_data(line):
            results.append(relevant_data)
    
    return {"parsed_results": results}
```

### Step 4: Add Tests

```python
# tests/test_your_tool.py

import pytest
from quarr.tools.your_category import your_tool_handler

def test_your_tool_basic():
    """Test basic functionality."""
    result = your_tool_handler({"target": "127.0.0.1"})
    assert result["status"] == "success"

def test_your_tool_invalid_input():
    """Test error handling."""
    result = your_tool_handler({"target": ""})
    assert result["status"] == "failed"
```

### Step 5: Update Documentation

Add tool documentation to:
- `docs/en/API_REFERENCE.md`
- `docs/id/API_REFERENCE.md`

---

## 6. Code Style

### Python Style

We follow PEP 8 with some modifications:

```bash
# Format code with Black
black quarr/ tests/ --line-length 100

# Check with flake8
flake8 quarr/ tests/ --max-line-length 100

# Type checking with mypy
mypy quarr/ --ignore-missing-imports
```

### Naming Conventions

| Type | Convention | Example |
|------|------------|---------|
| Functions | snake_case | `parse_nmap_output()` |
| Classes | PascalCase | `ToolRegistry` |
| Constants | UPPER_SNAKE | `MAX_AGENT_STEPS` |
| Tool names | snake_case | `web_content_discovery` |
| File names | snake_case | `active_directory.py` |

### Docstrings

Use Google-style docstrings:

```python
def function_name(param1: str, param2: int = 10) -> dict:
    """
    Brief description of function.
    
    Longer description if needed.
    
    Args:
        param1: Description of param1
        param2: Description of param2, defaults to 10
        
    Returns:
        Description of return value
        
    Raises:
        ValueError: When param1 is empty
        
    Example:
        >>> result = function_name("test", 5)
        >>> print(result)
    """
    pass
```

---

## 7. Testing

### Run All Tests

```bash
python3 -m pytest tests/ -v
```

### Run Specific Tests

```bash
# Run single test file
python3 -m pytest tests/test_quarr.py -v

# Run specific test
python3 -m pytest tests/test_quarr.py::test_function_name -v

# Run with coverage
python3 -m pytest tests/ --cov=quarr --cov-report=html
```

### Test Categories

```bash
# Unit tests only
python3 -m pytest tests/ -m "unit"

# Integration tests (require tools installed)
python3 -m pytest tests/ -m "integration"
```

### Writing Tests

```python
import pytest
from quarr.core.models import Finding, FindingStatus

class TestFinding:
    """Tests for Finding model."""
    
    def test_finding_creation(self):
        """Test creating a new finding."""
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
        """Test severity ranking."""
        finding = Finding(severity=severity)
        assert finding.severity_rank == expected
```

---

## 8. Submitting Changes

### Branch Naming

```bash
# Feature branch
git checkout -b feature/add-new-tool

# Bug fix branch
git checkout -b fix/parser-error

# Documentation branch
git checkout -b docs/update-readme
```

### Commit Messages

Follow conventional commits:

```
<type>(<scope>): <description>

[optional body]

[optional footer]
```

Types:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation
- `style`: Code style (formatting)
- `refactor`: Code refactoring
- `test`: Adding tests
- `chore`: Maintenance

Examples:

```bash
git commit -m "feat(tools): add SNMP enumeration tool"
git commit -m "fix(parser): handle empty nmap output"
git commit -m "docs: update installation guide"
```

### Before Submitting

```bash
# Update from upstream
git fetch upstream
git rebase upstream/main

# Run checks
black quarr/ tests/
flake8 quarr/ tests/
python3 -m pytest tests/ -v

# Push to your fork
git push origin feature/your-feature
```

---

## 9. Pull Request Guidelines

### PR Checklist

- [ ] Code follows project style guidelines
- [ ] Tests added for new functionality
- [ ] All tests pass
- [ ] Documentation updated
- [ ] Commit messages follow convention
- [ ] PR description explains changes

### PR Template

```markdown
## Description
Brief description of changes.

## Type of Change
- [ ] New feature
- [ ] Bug fix
- [ ] Documentation update
- [ ] Refactoring

## Testing
How was this tested?

## Checklist
- [ ] Tests pass
- [ ] Documentation updated
- [ ] Code formatted with Black
```

### Review Process

1. Submit PR to `main` branch
2. Automated checks run (CI)
3. Maintainer reviews code
4. Address feedback if needed
5. PR merged after approval

---

## 10. Reporting Issues

### Bug Reports

Include:
- QUARR version
- Python version
- Operating system
- Steps to reproduce
- Expected behavior
- Actual behavior
- Error messages/logs

### Feature Requests

Include:
- Use case description
- Proposed solution
- Alternative solutions considered
- Additional context

### Security Issues

For security vulnerabilities:
- **Do NOT** open public issues
- Email maintainers directly
- Include detailed description
- Allow time for fix before disclosure

---

## Questions?

- Open a GitHub Discussion for questions
- Join our community chat (if available)
- Check existing issues before creating new ones

Thank you for contributing! 🎉
