"""
Entry point. Run as:  python -m scraper.main

For every active source in sources.yaml:
  - call its fetcher
  - on any exception, record it under run["blocked"] and move on (one bad
    source never sinks the run)
  - on success, record it under run["reached"]

All fetched items are then deduped against state/seen.json, split by tier,
and written to:
  - digest/latest.json   (always overwritten — this is what the Claude
    routine fetches by a stable raw-GitHub URL every morning)
  - digest/YYYY-MM-DD.json (a dated copy, kept for history/debugging)

state/seen.json is updated with today's newly-surfaced uids and pruned of
anything past its retention window, then saved — this is the piece that lets
tomorrow's run know what's already been reported, something no agent-based
run ever had.

Nothing in this file calls an LLM. It is pure data plumbing; the judgment
step (turning these facts into the brief's prose) happens afterward, in the
Claude routine, on the small digest this produces.
"""

from __future__ import annotations

import datetime as dt
import json
import sys
import traceback
from pathlib import Path

import yaml

from . import state as state_mod
from .fetchers import FETCHERS

ROOT = Path(__file__).resolve().parent.parent
SOURCES_FILE = ROOT / "sources.yaml"
STATE_FILE = ROOT / "state" / "seen.json"
DIGEST_DIR = ROOT / "digest"


def load_sources() -> dict:
    return yaml.safe_load(SOURCES_FILE.read_text(encoding="utf-8"))


def run_tier(tier_key: str, sources: list[dict], run_log: dict) -> list[dict]:
    items: list[dict] = []
    for src in sources:
        if not src.get("active", True):
            continue
        src = {**src, "_tier": tier_key.replace("tier", "")}
        fetcher = FETCHERS.get(src["type"])
        if fetcher is None:
            run_log["blocked"].append(f"{src['id']} (unknown type '{src['type']}')")
            continue
        try:
            fetched = fetcher(src)
            items.extend(fetched)
            run_log["reached"].append(f"{src['id']} ({len(fetched)})")
        except Exception as exc:  # noqa: BLE001 — a single source's failure must never kill the run
            run_log["blocked"].append(f"{src['id']} ({exc.__class__.__name__}: {exc})")
    return items


def main() -> int:
    sources = load_sources()
    run_log = {"reached": [], "blocked": []}

    all_items: list[dict] = []
    for tier_key in ("tier1", "tier2", "tier3"):
        all_items.extend(run_tier(tier_key, sources.get(tier_key, []), run_log))

    state = state_mod.load(STATE_FILE)
    state = state_mod.prune(state)
    new_items = state_mod.filter_new(state, all_items)
    state_mod.record(state, new_items)
    state_mod.save(STATE_FILE, state)

    by_tier = {"1": [], "2": [], "3": []}
    for item in new_items:
        by_tier.setdefault(item["tier"], []).append(item)
    for tier_items in by_tier.values():
        tier_items.sort(key=lambda i: i["date"], reverse=True)

    today = dt.datetime.now(dt.timezone.utc).date().isoformat()
    digest = {
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "date": today,
        "counts": {tier: len(tier_items) for tier, tier_items in by_tier.items()},
        "sources": run_log,
        "items": by_tier,
    }

    DIGEST_DIR.mkdir(parents=True, exist_ok=True)
    (DIGEST_DIR / "latest.json").write_text(json.dumps(digest, indent=2), encoding="utf-8")
    (DIGEST_DIR / f"{today}.json").write_text(json.dumps(digest, indent=2), encoding="utf-8")

    total = sum(digest["counts"].values())
    print(
        f"Perimeter Brief pipeline — {today}: "
        f"{total} new item(s) (t1={digest['counts']['1']} t2={digest['counts']['2']} t3={digest['counts']['3']}), "
        f"{len(run_log['reached'])} source(s) reached, {len(run_log['blocked'])} blocked."
    )
    if run_log["blocked"]:
        print("Blocked sources:", ", ".join(run_log["blocked"]), file=sys.stderr)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception:  # noqa: BLE001 — surface a full traceback in the Actions log, but always exit non-zero cleanly
        traceback.print_exc()
        sys.exit(1)
