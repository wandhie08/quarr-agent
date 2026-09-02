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
import shutil
import zipfile
from datetime import datetime
from pathlib import Path

from quarr.core.models import PentestState

ENGAGEMENTS_DIR = "engagements"


def _get_engagement_dir(engagement_id: str) -> Path:
    p = Path(ENGAGEMENTS_DIR) / engagement_id
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
    filepath = Path(ENGAGEMENTS_DIR) / engagement_id / "state.json"
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
    eng_dir = Path(ENGAGEMENTS_DIR) / engagement_id
    if eng_dir.exists():
        shutil.rmtree(eng_dir)
        return True
    return False


def save_evidence(engagement_id: str, filename: str, content: str) -> str:
    """Save evidence file."""
    eng_dir = _get_engagement_dir(engagement_id)
    filepath = eng_dir / "evidence" / filename
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
