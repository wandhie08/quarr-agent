"""Unit tests for Phase 4 validators."""

import pytest

from quarr.core.exceptions import (
    ArgumentValidationError,
    TargetValidationError,
    ValidationError,
)
from quarr.core.validators import command as cv
from quarr.core.validators import file as fv
from quarr.core.validators import path as pv
from quarr.core.validators import target as tv

# ---- target ----

@pytest.mark.unit
@pytest.mark.parametrize("t,expected", [
    ("10.10.10.20", "10.10.10.20"),
    ("https://target.lab.local/path?x=1", "target.lab.local"),
    ("10.10.10.0/24", "10.10.10.0/24"),
    ("TARGET.EXAMPLE.COM", "target.example.com"),
])
def test_target_normalize_valid(t, expected):
    assert tv.normalize(t) == expected


@pytest.mark.unit
@pytest.mark.parametrize("bad", ["10.0.0.1; rm -rf /", "a b", "$(id)", "a|b", ""])
def test_target_rejects_bad(bad):
    with pytest.raises(TargetValidationError):
        tv.normalize(bad)


@pytest.mark.unit
def test_target_rejects_loopback_when_disallowed():
    with pytest.raises(TargetValidationError):
        tv.normalize("127.0.0.1", allow_private=False)


# ---- command ----

@pytest.mark.unit
@pytest.mark.parametrize("bad", [
    "; rm -rf /", "a|b", "$(whoami)", "`id`", "a>b", "new\nline",
])
def test_command_rejects_injection(bad):
    with pytest.raises(ArgumentValidationError):
        cv.validate_arg(bad)


@pytest.mark.unit
@pytest.mark.parametrize("url", [
    "http://site.com/page?id=1",
    "http://site.com/page?id=1&cat=2",
    "https://a.b/path#frag",
])
def test_command_accepts_parameterized_urls(url):
    # URL query/fragment chars are safe under shell=False and are REQUIRED by
    # SQLi/nuclei/web tools against realistic targets.
    assert cv.validate_arg(url) == url


@pytest.mark.unit
def test_command_accepts_flags_and_values():
    cv.validate_argv(["nmap", "-sV", "-oX", "-", "10.0.0.1"])
    cv.validate_argv(["nuclei", "-u", "https://example.com", "-jsonl"])


# ---- path ----

@pytest.mark.unit
def test_path_within_base_ok(tmp_path):
    f = tmp_path / "a.txt"
    f.write_text("x")
    assert pv.validate_within(str(f), str(tmp_path)).endswith("a.txt")


@pytest.mark.unit
def test_path_traversal_rejected(tmp_path):
    with pytest.raises(ValidationError):
        pv.validate_within(str(tmp_path / ".." / "escape.txt"), str(tmp_path))


@pytest.mark.unit
def test_symlink_escape_rejected(tmp_path):
    import os
    outside = tmp_path.parent / "outside_secret.txt"
    outside.write_text("secret")
    link = tmp_path / "link.txt"
    os.symlink(str(outside), str(link))
    with pytest.raises(ValidationError):
        pv.validate_within(str(link), str(tmp_path))


# ---- file ----

@pytest.mark.unit
def test_file_allowed_extension(tmp_path):
    f = tmp_path / "note.txt"
    f.write_text("hi")
    assert fv.validate_file(str(f), "evidence", str(tmp_path))


@pytest.mark.unit
def test_file_disallowed_extension(tmp_path):
    f = tmp_path / "bad.exe"
    f.write_text("x")
    with pytest.raises(ValidationError):
        fv.validate_file(str(f), "evidence", str(tmp_path))


@pytest.mark.unit
def test_file_oversize(tmp_path):
    f = tmp_path / "big.txt"
    f.write_text("x" * 100)
    with pytest.raises(ValidationError):
        fv.validate_file(str(f), "evidence", str(tmp_path), max_bytes=10)
