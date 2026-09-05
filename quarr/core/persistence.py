"""
persistence.py - M9: Persistent State

Save/load engagement state ke disk.
Bisa resume sesi kemarin tanpa ulang dari awal.

Files:
- engagements/<id>/state.json    — full state
- engagements/<id>/evidence/     — collected evidence files
"""

import hashlib as _hashlib
import json
import os
import re
import shutil
import zipfile
from datetime import datetime
from pathlib import Path

from quarr.core.exceptions import ValidationError
from quarr.core.models import PentestState
from quarr.core.validators.path import safe_join

ENGAGEMENTS_DIR = "engagements"

# Engagement IDs and evidence filenames are used to build filesystem paths, so
# they must be strictly validated to prevent traversal / arbitrary FS access.
_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")


def _validate_engagement_id(engagement_id: str) -> str:
    if not engagement_id or not _ID_RE.match(engagement_id) or engagement_id in (".", ".."):
        raise ValidationError(
            "Invalid engagement id", context={"engagement_id": str(engagement_id)}
        )
    return engagement_id


def _validate_filename(filename: str) -> str:
    # Evidence filenames must be a single path component with no traversal.
    if (
        not filename
        or "/" in filename
        or "\\" in filename
        or filename in (".", "..")
        or "\x00" in filename
    ):
        raise ValidationError("Invalid evidence filename", context={"filename": str(filename)})
    return filename


def _get_engagement_dir(engagement_id: str) -> Path:
    _validate_engagement_id(engagement_id)
    # safe_join resolves + asserts containment within ENGAGEMENTS_DIR.
    p = Path(safe_join(ENGAGEMENTS_DIR, engagement_id))
    p.mkdir(parents=True, exist_ok=True)
    (p / "evidence").mkdir(exist_ok=True)
    return p


def save_state(state: PentestState) -> str:
    """Save state ke disk. Returns filepath."""
    eng_dir = _get_engagement_dir(state.engagement.id)
    filepath = eng_dir / "state.json"

    data = state.model_dump(mode="json")
    data["_saved_at"] = datetime.now().isoformat()

    with open(filepath, "w") as f:
        json.dump(data, f, indent=2, default=str)

    return str(filepath)


def load_state(engagement_id: str) -> PentestState | None:
    """Load state dari disk."""
    _validate_engagement_id(engagement_id)
    eng_dir = Path(safe_join(ENGAGEMENTS_DIR, engagement_id))
    filepath = eng_dir / "state.json"
    if not filepath.exists():
        return None

    with open(filepath) as f:
        data = json.load(f)

    data.pop("_saved_at", None)
    return PentestState.model_validate(data)


def list_engagements() -> list:
    """List semua saved engagements."""
    base = Path(ENGAGEMENTS_DIR)
    if not base.exists():
        return []

    results = []
    for d in sorted(base.iterdir()):
        state_file = d / "state.json"
        if state_file.exists():
            try:
                with open(state_file) as f:
                    data = json.load(f)
                eng = data.get("engagement", {})
                results.append(
                    {
                        "id": eng.get("id", d.name),
                        "name": eng.get("name", "Unknown"),
                        "scope": eng.get("allowed_targets", []),
                        "findings": len(data.get("findings", [])),
                        "hosts": len(data.get("hosts", [])),
                        "tools_run": len(data.get("tool_history", [])),
                        "saved_at": data.get("_saved_at", "unknown"),
                    }
                )
            except Exception:
                pass
    return results


def delete_engagement(engagement_id: str) -> bool:
    """Delete saved engagement."""
    _validate_engagement_id(engagement_id)
    eng_dir = Path(safe_join(ENGAGEMENTS_DIR, engagement_id))
    if eng_dir.exists():
        shutil.rmtree(eng_dir)
        return True
    return False


def save_evidence(engagement_id: str, filename: str, content: str) -> str:
    """Save evidence file."""
    _validate_filename(filename)
    eng_dir = _get_engagement_dir(engagement_id)
    # Contain the final path within the engagement's evidence directory.
    filepath = Path(safe_join(str(eng_dir / "evidence"), filename))
    with open(filepath, "w") as f:
        f.write(content)
    return str(filepath)


# ============================================================
# Session bundle export/import (Phase 5)
# ============================================================


def _reject_zip_slip(member: str, dest_base: str) -> None:
    target = os.path.realpath(os.path.join(dest_base, member))
    base = os.path.realpath(dest_base)
    if target != base and not target.startswith(base + os.sep):
        from quarr.core.exceptions import ValidationError

        raise ValidationError(
            "Archive member escapes destination (zip-slip)",
            context={"member": member},
        )


def export_bundle(engagement_id: str, out_path: str) -> str:
    """Zip an engagement's state + evidence into a portable bundle."""
    eng_dir = Path(ENGAGEMENTS_DIR) / engagement_id
    with zipfile.ZipFile(out_path, "w", zipfile.ZIP_DEFLATED) as z:
        for root, _dirs, files in os.walk(eng_dir):
            for name in files:
                full = Path(root) / name
                arcname = full.relative_to(Path(ENGAGEMENTS_DIR))
                z.write(full, str(arcname))
    return out_path


def import_bundle(bundle_path: str, dest_base: str = None):
    """Import a session bundle, rejecting zip-slip and verifying evidence hashes."""
    dest_base = dest_base or ENGAGEMENTS_DIR
    Path(dest_base).mkdir(parents=True, exist_ok=True)

    engagement_id = None
    with zipfile.ZipFile(bundle_path) as z:
        for member in z.namelist():
            _reject_zip_slip(member, dest_base)
            if member.endswith("state.json"):
                engagement_id = member.split("/")[0]
        z.extractall(dest_base)

    if engagement_id is None:
        from quarr.core.exceptions import ValidationError

        raise ValidationError("Bundle missing state.json")

    # Verify evidence hashes against the index (warn on mismatch).
    warnings = []
    index_path = Path(dest_base) / engagement_id / "evidence" / "index.json"
    if index_path.exists():
        with open(index_path) as f:
            index = json.load(f)
        for entry in index:
            fp = entry.get("filepath")
            expected = entry.get("sha256")
            if fp and expected and os.path.exists(fp):
                with open(fp, "rb") as fh:
                    actual = _hashlib.sha256(fh.read()).hexdigest()
                if actual != expected:
                    warnings.append(entry.get("id"))

    prev = ENGAGEMENTS_DIR
    try:
        globals()["ENGAGEMENTS_DIR"] = dest_base
        state = load_state(engagement_id)
    finally:
        globals()["ENGAGEMENTS_DIR"] = prev
    return state, warnings
