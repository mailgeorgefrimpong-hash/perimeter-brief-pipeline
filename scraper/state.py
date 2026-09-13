"""
Dedup state — the persistent memory the old agent-based pipeline never had.

state/seen.json holds every item `uid` this pipeline has ever surfaced, each
with the date it was first seen. On every run:
  1. load the existing file
  2. drop entries older than RETENTION_DAYS (an item that scrolled off any
     source's own window_days ago can never resurface anyway, so keeping it
     forever is pointless)
  3. after fetching, anything whose uid is already in the store is filtered
     out of today's digest — it was already reported, don't repeat it
  4. every genuinely new uid gets added back before saving

This file is committed back to the repo by the GitHub Actions workflow after
each run, so the "memory" persists between runs the same way a database would.
"""

from __future__ import annotations

import datetime as dt
import json
from pathlib import Path

RETENTION_DAYS = 45


def load(path: Path) -> dict:
    if not path.exists():
        return {"seen": {}}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        # A corrupt state file should never crash the run — start clean rather
        # than block every future edition. Whatever it would have deduped
        # against just gets a one-time re-surface instead.
        return {"seen": {}}


def prune(state: dict) -> dict:
    cutoff = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=RETENTION_DAYS)).date().isoformat()
    seen = state.get("seen", {})
    state["seen"] = {uid: seen_date for uid, seen_date in seen.items() if seen_date >= cutoff}
    return state


def filter_new(state: dict, items: list[dict]) -> list[dict]:
    seen = state.get("seen", {})
    return [item for item in items if item["uid"] not in seen]


def record(state: dict, items: list[dict]) -> None:
    today = dt.datetime.now(dt.timezone.utc).date().isoformat()
    for item in items:
        state.setdefault("seen", {})[item["uid"]] = today


def save(path: Path, state: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(state, indent=2, sort_keys=True), encoding="utf-8")
