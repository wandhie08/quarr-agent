"""Unit tests for structured logging (Phase 1, Req 4 & 5.7)."""

import json
import logging

import pytest
import structlog

from quarr.core import logging as qlog


@pytest.fixture(autouse=True)
def reset_structlog():
    structlog.contextvars.clear_contextvars()
    yield
    structlog.contextvars.clear_contextvars()


@pytest.mark.unit
def test_redaction_processor_masks_top_level_and_nested():
    proc = qlog._make_redaction_processor(qlog.DEFAULT_REDACT_KEYS)
    event = {
        "event": "call",
        "api_key": "sk-secret",
        "payload": {"password": "hunter2", "safe": "ok"},
        "items": [{"token": "abc"}, {"host": "10.0.0.1"}],
    }
    out = proc(None, "info", event)
    assert out["api_key"] == qlog._REDACTED
    assert out["payload"]["password"] == qlog._REDACTED
    assert out["payload"]["safe"] == "ok"
    assert out["items"][0]["token"] == qlog._REDACTED
    assert out["items"][1]["host"] == "10.0.0.1"


@pytest.mark.unit
def test_correlation_id_binds_and_propagates():
    qlog.configure_logging(level="DEBUG", fmt="json")
    cid = qlog.bind_correlation_id("fixedcid1234")
    assert cid == "fixedcid1234"
    assert qlog.get_correlation_id() == "fixedcid1234"


@pytest.mark.unit
def test_json_format_is_parseable_and_redacts(capsys):
    qlog.configure_logging(level="INFO", fmt="json")
    log = qlog.get_logger("quarr.test")
    log.info("secret_event", api_key="sk-should-not-appear", host="10.0.0.5")
    captured = capsys.readouterr()
    line = captured.err.strip().splitlines()[-1]
    parsed = json.loads(line)
    assert parsed["event"] == "secret_event"
    assert parsed["api_key"] == qlog._REDACTED
    assert parsed["host"] == "10.0.0.5"
    assert "sk-should-not-appear" not in line


@pytest.mark.unit
def test_stdlib_logging_routed(capsys):
    qlog.configure_logging(level="INFO", fmt="json")
    logging.getLogger("quarr.legacy").info("legacy message")
    captured = capsys.readouterr()
    assert "legacy message" in captured.err
