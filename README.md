# Perimeter Brief — scraping pipeline

Deterministic, zero-LLM-token half of the [Perimeter Brief](https://claude.ai/code/artifact/824df816-673d-4e1a-bff9-e38956880b76)
daily briefing. This repo does the *pulling* — hitting known feeds/APIs,
filtering to what's new, and remembering what's already been reported.
Claude does only the *writing* — turning the small digest this produces into
the brief's three-part entries and publishing the page.

## Why this exists

The brief used to run as 3 full agentic research passes every single day —
each one deciding from scratch what to search for and reading raw web pages
to figure out what mattered, even for sources that publish a plain RSS feed
or JSON API. That's real reasoning work repeated daily for zero reason: a
government CVE feed doesn't need an LLM to "decide" whether to check it.

So the split is:

| | Who does it | Why |
|---|---|---|
| **Pulling** (this repo) | A scheduled Python script on GitHub Actions | Every source here has a fixed, known shape — a script can hit it exactly and pull exact fields, with no interpretation needed and no tokens spent. |
| **Deduping** (this repo) | `state/seen.json`, committed after every run | So "what's new since last time" is a plain lookup, not something an LLM has to be told or re-derive. |
| **Writing / judgment** (the Claude routine) | Reads `digest/latest.json` | Turning a bare fact into the brief's "What it is / In plain terms / Recommended action" is genuine synthesis — that's the one part that actually needs a language model. |

Output is meant to be materially the same brief, at a fraction of the tokens
per edition — see the Claude-side integration section below for exactly what
changed there.

## Layout

```
sources.yaml              Every tracked source: id, tier, type, URL, window.
scraper/
  fetchers.py              One function per source `type` — plain HTTP + parsing, no LLM.
  state.py                 Dedup store (state/seen.json): what's already been surfaced.
  main.py                  Orchestrates fetch → dedup → digest. Run: `python -m scraper.main`
state/seen.json            Persisted dedup memory. Committed back to the repo each run.
digest/latest.json         Always-current digest — what the Claude routine fetches.
digest/YYYY-MM-DD.json     Dated copy of each day's digest, kept for history/debugging.
.github/workflows/daily-scrape.yml   Runs the whole thing on GitHub's own runners, no local machine involved.
```

## Adding / fixing a source

Edit `sources.yaml`. Each entry needs a real `type` from `scraper/fetchers.py`'s
`FETCHERS` map (`rss`, `cisa_kev`, `nvd_cve`, `statuspage_json`, `slack_status`,
`github_advisories`, `hn_algolia`, `stackexchange`, `github_issues_search`).
Set `active: false` with a `note:` for anything that doesn't have a verified
working endpoint yet — never guess a URL. A few sources are already marked
this way (see the comments in `sources.yaml`) because they failed a direct
check as of 2026-09-13: Okta/Salesforce status (non-standard API shape),
Cisco/Fortinet bulletins (no clean unauthenticated feed), and three Tier-2
bloggers whose feeds didn't resolve cleanly (robichaux.net, nathanmcnulty.com,
Mary Jo Foley/ZDNet). Re-check these periodically and flip `active: true` once
confirmed.

LinkedIn, Quora, and Reddit are deliberately **not** in this pipeline — none
of them offers a stable, official, unauthenticated read API (Reddit's public
`.json` endpoints routinely 403 from data-center IPs, which is exactly what
past editions of the brief already logged). If you want that signal covered,
that stays a small, occasional WebSearch job on the Claude side — not
something worth scripting against platforms that don't support it.

## Running locally

```
pip install -r requirements.txt
python -m scraper.main
```

Prints a one-line summary and writes `digest/latest.json` +
`digest/<today>.json`. `state/seen.json` is updated in place.

## The GitHub Actions schedule

`.github/workflows/daily-scrape.yml` runs at **06:30 UTC**, 30 minutes before
the Claude routine's 07:00 UTC run, so the digest is always fresh when the
brief gets written. It needs no secrets — every source here is public, and
the workflow's own built-in `GITHUB_TOKEN` (automatic, no setup) is used only
to get a friendlier rate limit on GitHub's own APIs (Advisories, Issues
search).

## Claude-side integration

The Claude routine (its full spec lives in the `Perimeter Brief · Ops`
artifact) had its STEP 4 changed from "run 3 parallel research subagents"
to: fetch `https://raw.githubusercontent.com/<owner>/perimeter-brief-pipeline/main/digest/latest.json`
and write each tier's entries directly from that digest's `items` — same
three-part write-up pattern, same tiers, same artifact. See
`routine-step4-replacement.md` in this repo for the exact replacement text
that was applied.
