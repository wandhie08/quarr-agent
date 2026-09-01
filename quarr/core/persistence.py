"""
persistence.py - M9: Persistent State

Save/load engagement state ke disk.
Bisa resume sesi kemarin tanpa ulang dari awal.

Files:
- engagements/<id>/state.json    — full state
- engagements/<id>/evidence/     — collected evidence files
"""

import json
import os
import shutil
from datetime import datetime
from pathlib import Path
from typing import Optional

from quarr.core.models import PentestState, Engagement


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


def load_state(engagement_id: str) -> Optional[PentestState]:
    """Load state dari disk."""
    filepath = Path(ENGAGEMENTS_DIR) / engagement_id / "state.json"
    if not filepath.exists():
        return None

    with open(filepath, "r") as f:
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
                results.append({
                    "id": eng.get("id", d.name),
                    "name": eng.get("name", "Unknown"),
                    "scope": eng.get("allowed_targets", []),
                    "findings": len(data.get("findings", [])),
                    "hosts": len(data.get("hosts", [])),
                    "tools_run": len(data.get("tool_history", [])),
                    "saved_at": data.get("_saved_at", "unknown"),
                })
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
