"""
logging.py - Structured Logging (structlog)

Configures structlog for JSON (production) or console (development) output,
with automatic correlation IDs, ISO-8601 UTC timestamps, and a redaction
processor that masks secret values before they reach any sink.

Usage:
    from quarr.core.logging import configure_logging, get_logger, bind_correlation_id
    configure_logging(level="INFO", fmt="console")
    log = get_logger("quarr.agent")
    bind_correlation_id()
    log.info("event_name", key="value")
"""

import logging
import sys
import uuid
from contextvars import ContextVar
from typing import Any

import structlog

# Correlation ID carried across all logs within one logical operation.
_correlation_id: ContextVar[str | None] = ContextVar("correlation_id", default=None)

DEFAULT_REDACT_KEYS = [
    "api_key",
    "apikey",
    "authorization",
    "password",
    "passwd",
    "pwd",
    "secret",
    "token",
    "credential",
    "credentials",
    "openai_api_key",
]

_REDACTED = "***REDACTED***"
_configured = False


def get_correlation_id() -> str | None:
    """Return the current correlation ID, if any."""
    return _correlation_id.get()


def bind_correlation_id(cid: str | None = None) -> str:
    """Generate/set a correlation ID for the current context and bind it."""
    cid = cid or uuid.uuid4().hex[:12]
    _correlation_id.set(cid)
    structlog.contextvars.bind_contextvars(correlation_id=cid)
    return cid


def _make_redaction_processor(redact_keys: list[str]):
    lowered = {k.lower() for k in redact_keys}

    def _redact(value: Any) -> Any:
        if isinstance(value, dict):
            return {
                k: (_REDACTED if k.lower() in lowered else _redact(v)) for k, v in value.items()
            }
        if isinstance(value, (list, tuple)):
            return type(value)(_redact(v) for v in value)
        return value

    def processor(logger, method_name, event_dict):
        for key in list(event_dict.keys()):
            if key.lower() in lowered:
                event_dict[key] = _REDACTED
            else:
                event_dict[key] = _redact(event_dict[key])
        return event_dict

    return processor


def configure_logging(
    level: str = "INFO",
    fmt: str = "console",
    redact_keys: list[str] | None = None,
) -> None:
    """
    Configure structlog and route the stdlib root logger through it.

    Args:
        level: DEBUG | INFO | WARNING | ERROR | CRITICAL
        fmt: "console" (human-readable) or "json" (production)
        redact_keys: keys whose values are masked in logs
    """
    global _configured

    redact_keys = redact_keys or DEFAULT_REDACT_KEYS
    log_level = getattr(logging, level.upper(), logging.INFO)

    shared_processors = [
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        structlog.processors.StackInfoRenderer(),
        _make_redaction_processor(redact_keys),
    ]

    if fmt == "json":
        renderer = structlog.processors.JSONRenderer()
    else:
        renderer = structlog.dev.ConsoleRenderer(colors=sys.stderr.isatty())

    structlog.configure(
        processors=shared_processors
        + [
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.make_filtering_bound_logger(log_level),
        cache_logger_on_first_use=True,
    )

    # Route stdlib logging (legacy logging.getLogger("quarr.*")) through structlog.
    formatter = structlog.stdlib.ProcessorFormatter(
        foreign_pre_chain=shared_processors,
        processors=[
            structlog.stdlib.ProcessorFormatter.remove_processors_meta,
            renderer,
        ],
    )
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(formatter)

    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(log_level)

    _configured = True


def get_logger(name: str) -> Any:
    """Return a bound structlog logger. Configures with defaults if needed."""
    if not _configured:
        configure_logging()
    return structlog.get_logger(name)
