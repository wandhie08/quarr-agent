"""Tests for tamper-evident evidence chain-of-custody (HMAC-signed index)."""

import json

import pytest

from quarr.core.evidence import EvidenceCollector


@pytest.fixture
def custody_key(monkeypatch):
    monkeypatch.setenv("QUARR_CUSTODY_KEY", "unit-test-custody-key")
    return "unit-test-custody-key"


@pytest.mark.unit
class TestChainOfCustodySignature:
    def test_index_is_signed(self, tmp_path, custody_key):
        ec = EvidenceCollector("ENG-1", base_dir=str(tmp_path))
        ec.collect("FIND-1", "nmap", "scan", content="22/tcp open")
        ec.save_index()
        res = ec.verify_index_signature()
        assert res["signed"] and res["valid"]

    def test_detects_index_tampering(self, tmp_path, custody_key):
        ec = EvidenceCollector("ENG-1", base_dir=str(tmp_path))
        ec.collect("FIND-1", "sqlmap", "sqli", content="injectable")
        idx = ec.save_index()
        # Attacker edits a recorded hash in the index.
        data = json.loads(open(idx).read())
        data[0]["sha256"] = "0" * 64
        with open(idx, "w") as f:
            f.write(json.dumps(data, indent=2))
        res = ec.verify_index_signature()
        assert res["signed"] and not res["valid"]
        assert "tampered" in res["reason"].lower()

    def test_attacker_cannot_forge_without_key(self, tmp_path, monkeypatch):
        # Sign with the real key...
        monkeypatch.setenv("QUARR_CUSTODY_KEY", "real-secret-key")
        ec = EvidenceCollector("ENG-1", base_dir=str(tmp_path))
        ec.collect("FIND-1", "nikto", "finding", content="x")
        idx = ec.save_index()
        # Attacker tampers evidence + recomputes signature with a WRONG key.
        import hashlib
        import hmac
        data = json.loads(open(idx).read())
        data[0]["description"] = "sanitized by attacker"
        raw = json.dumps(data, indent=2)
        with open(idx, "w") as f:
            f.write(raw)
        forged = hmac.new(b"attacker-guess", raw.encode(), hashlib.sha256).hexdigest()
        with open(idx + ".sig", "w") as f:
            f.write(forged)
        # Verifier (holding the real key) rejects the forgery.
        res = ec.verify_index_signature()
        assert not res["valid"]

    def test_missing_signature_flagged(self, tmp_path, custody_key):
        ec = EvidenceCollector("ENG-1", base_dir=str(tmp_path))
        ec.collect("FIND-1", "nmap", "scan", content="x")
        ec.save_index()
        # Remove the signature file.
        (tmp_path / "ENG-1" / "evidence" / "index.json.sig").unlink()
        res = ec.verify_index_signature()
        assert not res["valid"] and "signature" in res["reason"].lower()

    def test_file_hash_tamper_still_detected_by_verify_chain(self, tmp_path, custody_key):
        # The existing per-file hash check still catches direct file edits.
        ec = EvidenceCollector("ENG-1", base_dir=str(tmp_path))
        ev = ec.collect("FIND-1", "nmap", "scan", content="original")
        with open(ev.filepath, "a") as f:
            f.write("\nattacker appended data")
        chain = ec.verify_chain()
        assert chain[0]["ok"] is False
