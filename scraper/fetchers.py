"""
Deterministic fetchers — one function per source `type` in sources.yaml.

None of this uses an LLM. Every function does the same thing every time it's
called: hit a known URL, parse a fixed structure, pull out fixed fields. No
"deciding what to search for", no interpretation of free text — that judgment
step happens later, in the Claude routine, on the small digest this produces.

Every fetcher returns a list of dicts with this common shape:
    {
        "uid": str,        # stable unique id for dedup (source_id + item's own id/url)
        "tier": "1"|"2"|"3",
        "source_id": str,  # matches sources.yaml id
        "source_name": str,
        "title": str,
        "url": str,
        "date": "YYYY-MM-DD",
        "summary": str,    # short factual snippet, NOT written prose — raw field(s) as given
        "author": str | None,
    }

A fetcher must never raise past its own boundary — main.py wraps every call
and records failures into the run's "blocked" list, exactly like the existing
Ops dashboard already does for sources that errored out during a research pass.
"""

from __future__ import annotations

import datetime as dt
import re
from typing import Any

import feedparser
import requests

TIMEOUT = 20
UA = "PerimeterBriefPipeline/1.0 (+https://github.com/; deterministic feed/API fetcher, no scraping of rendered pages)"


def _cutoff(window_days: int) -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=window_days)


def _parse_date(value: Any) -> dt.datetime | None:
    """Best-effort parse of a date string into an aware UTC datetime. Returns None, never raises."""
    if not value:
        return None
    if isinstance(value, (int, float)):
        try:
            return dt.datetime.fromtimestamp(value, tz=dt.timezone.utc)
        except (ValueError, OSError):
            return None
    text = str(value).strip()
    fmts = (
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%d %H:%M:%S%z",
        "%Y-%m-%d",
        "%a, %d %b %Y %H:%M:%S %z",
        "%a, %d %b %Y %H:%M:%S %Z",
    )
    for fmt in fmts:
        try:
            parsed = dt.datetime.strptime(text, fmt)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=dt.timezone.utc)
            return parsed
        except ValueError:
            continue
    return None


def fetch_cisa_kev(src: dict) -> list[dict]:
    r = requests.get(src["url"], timeout=TIMEOUT, headers={"User-Agent": UA})
    r.raise_for_status()
    data = r.json()
    cutoff = _cutoff(src.get("window_days", 7))
    out = []
    for vuln in data.get("vulnerabilities", []):
        added = _parse_date(vuln.get("dateAdded"))
        if added is None or added < cutoff:
            continue
        cve = vuln.get("cveID", "")
        out.append({
            "uid": f"cisa_kev:{cve}",
            "tier": "1",
            "source_id": src["id"],
            "source_name": src["name"],
            "title": f"{cve} — {vuln.get('vulnerabilityName', '')}".strip(" —"),
            "url": f"https://nvd.nist.gov/vuln/detail/{cve}" if cve else "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
            "date": added.date().isoformat(),
            "summary": (
                f"Vendor/product: {vuln.get('vendorProject', '?')} {vuln.get('product', '')}. "
                f"{vuln.get('shortDescription', '')} "
                f"Required action: {vuln.get('requiredAction', '')} "
                f"Due date: {vuln.get('dueDate', '')}. "
                f"Known ransomware use: {vuln.get('knownRansomwareCampaignUse', 'Unknown')}."
            ).strip(),
            "author": None,
        })
    return out


def fetch_nvd_cve(src: dict) -> list[dict]:
    cutoff = _cutoff(src.get("window_days", 7))
    now = dt.datetime.now(dt.timezone.utc)
    params = {
        "pubStartDate": cutoff.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "pubEndDate": now.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "cvssV3Severity": "CRITICAL",
        "resultsPerPage": 100,
    }
    r = requests.get(src["url"], params=params, timeout=TIMEOUT, headers={"User-Agent": UA})
    r.raise_for_status()
    data = r.json()
    min_cvss = src.get("min_cvss", 9.0)
    out = []
    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = cve.get("id", "")
        metrics = cve.get("metrics", {})
        score = None
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            entries = metrics.get(key) or []
            if entries:
                score = entries[0].get("cvssData", {}).get("baseScore")
                break
        if score is None or score < min_cvss:
            continue
        descs = cve.get("descriptions", [])
        desc = next((d["value"] for d in descs if d.get("lang") == "en"), "")
        published = _parse_date(cve.get("published"))
        out.append({
            "uid": f"nvd:{cve_id}",
            "tier": "1",
            "source_id": src["id"],
            "source_name": src["name"],
            "title": f"{cve_id} (CVSS {score})",
            "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            "date": (published or now).date().isoformat(),
            "summary": desc,
            "author": None,
        })
    return out


def fetch_rss(src: dict) -> list[dict]:
    parsed = feedparser.parse(src["url"], agent=UA, request_headers={"User-Agent": UA})
    cutoff = _cutoff(src.get("window_days", 10))
    out = []
    for entry in parsed.entries:
        published_struct = entry.get("published_parsed") or entry.get("updated_parsed")
        if published_struct:
            published = dt.datetime(*published_struct[:6], tzinfo=dt.timezone.utc)
        else:
            published = None
        if published is not None and published < cutoff:
            continue
        link = entry.get("link", "")
        summary = re.sub("<[^<]+?>", "", entry.get("summary", "") or entry.get("description", ""))[:600]
        out.append({
            "uid": f"{src['id']}:{link or entry.get('id', entry.get('title', ''))}",
            "tier": src.get("_tier", "2"),
            "source_id": src["id"],
            "source_name": src["name"],
            "title": entry.get("title", "").strip(),
            "url": link,
            "date": (published or dt.datetime.now(dt.timezone.utc)).date().isoformat(),
            "summary": summary.strip(),
            "author": entry.get("author"),
        })
    return out


def fetch_statuspage_json(src: dict) -> list[dict]:
    r = requests.get(src["url"], timeout=TIMEOUT, headers={"User-Agent": UA})
    r.raise_for_status()
    data = r.json()
    cutoff = _cutoff(src.get("window_days", 3))
    min_impact = src.get("min_impact", "minor")
    impact_rank = {"none": 0, "minor": 1, "major": 2, "critical": 3}
    floor = impact_rank.get(min_impact, 1)
    out = []
    for incident in data.get("incidents", []):
        created = _parse_date(incident.get("created_at"))
        if created is None or created < cutoff:
            continue
        if impact_rank.get(incident.get("impact", "none"), 0) < floor:
            continue
        latest_update = ""
        updates = incident.get("incident_updates", [])
        if updates:
            latest_update = updates[0].get("body", "")
        out.append({
            "uid": f"{src['id']}:{incident.get('id')}",
            "tier": "1",
            "source_id": src["id"],
            "source_name": src["name"],
            "title": incident.get("name", ""),
            "url": incident.get("shortlink") or data.get("page", {}).get("url", ""),
            "date": created.date().isoformat(),
            "summary": f"Impact: {incident.get('impact')}. Status: {incident.get('status')}. {latest_update}".strip(),
            "author": None,
        })
    return out


def fetch_slack_status(src: dict) -> list[dict]:
    r = requests.get(src["url"], timeout=TIMEOUT, headers={"User-Agent": UA})
    r.raise_for_status()
    data = r.json()
    # Slack's own status API shape: {"status": "ok"|"active", "date_created": "...", "date_updated": "...", "active_incidents": [...]}
    cutoff = _cutoff(src.get("window_days", 3))
    out = []
    for incident in data.get("active_incidents", []) or []:
        created = _parse_date(incident.get("date_created"))
        if created is None or created < cutoff:
            continue
        out.append({
            "uid": f"{src['id']}:{incident.get('id', incident.get('title'))}",
            "tier": "1",
            "source_id": src["id"],
            "source_name": src["name"],
            "title": incident.get("title", "Slack incident"),
            "url": "https://slack-status.com/",
            "date": created.date().isoformat(),
            "summary": (incident.get("notes", [{}])[-1].get("body", "") if incident.get("notes") else ""),
            "author": None,
        })
    return out


def fetch_github_advisories(src: dict) -> list[dict]:
    import os
    cutoff = _cutoff(src.get("window_days", 3))
    headers = {"User-Agent": UA, "Accept": "application/vnd.github+json"}
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    params = {"per_page": 50, "sort": "published", "direction": "desc"}
    r = requests.get(src["url"], params=params, headers=headers, timeout=TIMEOUT)
    r.raise_for_status()
    out = []
    for adv in r.json():
        published = _parse_date(adv.get("published_at"))
        if published is None or published < cutoff:
            continue
        severity = (adv.get("severity") or "").lower()
        if severity not in ("high", "critical"):
            continue
        out.append({
            "uid": f"ghsa:{adv.get('ghsa_id')}",
            "tier": "1",
            "source_id": src["id"],
            "source_name": src["name"],
            "title": f"{adv.get('ghsa_id')} — {adv.get('summary', '')}",
            "url": adv.get("html_url", ""),
            "date": published.date().isoformat(),
            "summary": (adv.get("description") or "")[:600],
            "author": None,
        })
    return out


def fetch_hn_algolia(src: dict) -> list[dict]:
    cutoff = _cutoff(src.get("window_days", 7))
    out = []
    seen_ids = set()
    for kw in src.get("keywords", []):
        params = {
            "query": kw,
            "tags": "story",
            "numericFilters": f"created_at_i>{int(cutoff.timestamp())}",
            "hitsPerPage": 20,
        }
        r = requests.get(src["url"], params=params, timeout=TIMEOUT, headers={"User-Agent": UA})
        r.raise_for_status()
        for hit in r.json().get("hits", []):
            oid = hit.get("objectID")
            if oid in seen_ids:
                continue
            seen_ids.add(oid)
            out.append({
                "uid": f"hn:{oid}",
                "tier": "3",
                "source_id": src["id"],
                "source_name": src["name"],
                "title": hit.get("title", ""),
                "url": hit.get("url") or f"https://news.ycombinator.com/item?id={oid}",
                "date": (_parse_date(hit.get("created_at")) or dt.datetime.now(dt.timezone.utc)).date().isoformat(),
                "summary": f"{hit.get('points', 0)} points, {hit.get('num_comments', 0)} comments. Matched keyword: {kw}.",
                "author": hit.get("author"),
            })
    return out


def fetch_stackexchange(src: dict) -> list[dict]:
    cutoff = _cutoff(src.get("window_days", 7))
    out = []
    for site in src.get("sites", []):
        params = {
            "order": "desc",
            "sort": "activity",
            "site": site,
            "pagesize": 20,
            "filter": "!9_bDDxJY5",  # includes body-less default fields; safe public filter
        }
        r = requests.get(src["url"], params=params, timeout=TIMEOUT, headers={"User-Agent": UA})
        r.raise_for_status()
        data = r.json()
        for q in data.get("items", []):
            created = _parse_date(q.get("creation_date"))
            if created is None or created < cutoff:
                continue
            out.append({
                "uid": f"se:{site}:{q.get('question_id')}",
                "tier": "3",
                "source_id": src["id"],
                "source_name": f"{src['name']} ({site})",
                "title": q.get("title", ""),
                "url": q.get("link", ""),
                "date": created.date().isoformat(),
                "summary": f"{q.get('view_count', 0)} views, {q.get('answer_count', 0)} answers. Tags: {', '.join(q.get('tags', []))}.",
                "author": (q.get("owner", {}) or {}).get("display_name"),
            })
    return out


def fetch_github_issues_search(src: dict) -> list[dict]:
    import os
    cutoff = _cutoff(src.get("window_days", 7))
    headers = {"User-Agent": UA, "Accept": "application/vnd.github+json"}
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    out = []
    for kw in src.get("keywords", []):
        q = f'{kw} in:title,body is:issue created:>{cutoff.strftime("%Y-%m-%d")}'
        params = {"q": q, "sort": "created", "order": "desc", "per_page": 10}
        r = requests.get(src["url"], params=params, headers=headers, timeout=TIMEOUT)
        if r.status_code == 403:
            # unauthenticated rate limit — skip this keyword rather than fail the whole source
            continue
        r.raise_for_status()
        for item in r.json().get("items", []):
            created = _parse_date(item.get("created_at"))
            out.append({
                "uid": f"ghissue:{item.get('id')}",
                "tier": "3",
                "source_id": src["id"],
                "source_name": src["name"],
                "title": item.get("title", ""),
                "url": item.get("html_url", ""),
                "date": (created or dt.datetime.now(dt.timezone.utc)).date().isoformat(),
                "summary": f"Repo: {item.get('repository_url', '').rsplit('/', 2)[-2:]}. Matched keyword: {kw}.",
                "author": (item.get("user", {}) or {}).get("login"),
            })
    return out


FETCHERS = {
    "cisa_kev": fetch_cisa_kev,
    "nvd_cve": fetch_nvd_cve,
    "rss": fetch_rss,
    "statuspage_json": fetch_statuspage_json,
    "slack_status": fetch_slack_status,
    "github_advisories": fetch_github_advisories,
    "hn_algolia": fetch_hn_algolia,
    "stackexchange": fetch_stackexchange,
    "github_issues_search": fetch_github_issues_search,
}
