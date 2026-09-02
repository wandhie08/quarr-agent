"""
file.py - File type/size validation (Phase 4), composed with path validation.
"""

import os

from quarr.core.exceptions import ValidationError
from quarr.core.validators import path as path_validator

ALLOWED_EXTENSIONS = {
    "evidence": {".txt", ".png", ".jpg", ".json", ".xml", ".log", ".pcap"},
    "wordlist": {".txt", ".lst", ".dic"},
    "hashfile": {".txt", ".hash"},
    "report": {".md", ".json", ".html", ".pdf"},
}


def validate_file(path: str, kind: str, base: str, max_bytes: int = 104_857_600) -> str:
    real = path_validator.validate_within(path, base)

    allowed = ALLOWED_EXTENSIONS.get(kind)
    if allowed is None:
        raise ValidationError("Unknown file kind", context={"kind": kind})

    ext = os.path.splitext(real)[1].lower()
    if ext not in allowed:
        raise ValidationError(
            "Disallowed file extension",
            context={"path": path, "ext": ext, "allowed": sorted(allowed)},
        )

    if os.path.exists(real) and os.path.getsize(real) > max_bytes:
        raise ValidationError(
            "File exceeds maximum size",
            context={"path": path, "max_bytes": max_bytes},
        )
    return real
