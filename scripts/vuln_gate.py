#!/usr/bin/env python3
"""Risk-based gate for Trivy image scan results.

Instead of failing on severity alone, each finding is enriched with:
  * CISA KEV  - is the CVE known to be exploited in the wild?
  * FIRST EPSS - probability of exploitation in the next 30 days.

Policy (first matching rule wins):
  1. In CISA KEV, any severity, fixed or not      -> BLOCK
  2. Enrichment unavailable, fixable HIGH/CRITICAL -> BLOCK (severity-only fallback)
  3. Fixable CRITICAL                              -> BLOCK
  4. Fixable HIGH with EPSS >= threshold           -> BLOCK
  5. Fixable HIGH with no EPSS score               -> BLOCK (cannot rule it out)
  6. Fixable HIGH with EPSS below threshold        -> WARN
  7. HIGH/CRITICAL with no fix available           -> WARN
  8. Everything else                               -> INFO

Findings marked not_affected/fixed by VEX are removed by Trivy before they get
here (run Trivy with --vex ... --show-suppressed) and are listed in the summary.

Only the standard library is used so the script runs on any CI image.
Exit code: 0 = pass, 1 = at least one BLOCK, 2 = usage/input error.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass
from typing import Iterable

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"
EPSS_BATCH = 100
USER_AGENT = "appsec-demon-vuln-gate/1.0"
HTTP_TIMEOUT = 30

BLOCK, WARN, INFO = "block", "warn", "info"
SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}
MAX_TABLE_ROWS = 50


@dataclass(frozen=True)
class Finding:
    target: str
    vuln_id: str
    pkg: str
    installed: str
    fixed: str
    severity: str
    title: str

    @property
    def fixable(self) -> bool:
        return bool(self.fixed)

    @property
    def rank(self) -> int:
        return SEVERITY_RANK.get(self.severity, 0)


@dataclass(frozen=True)
class Suppressed:
    target: str
    vuln_id: str
    pkg: str
    status: str
    statement: str
    source: str


@dataclass(frozen=True)
class Decision:
    finding: Finding
    action: str
    reason: str
    epss: float | None
    kev: bool


@dataclass
class Enrichment:
    kev: set[str]
    epss: dict[str, float]
    kev_ok: bool
    epss_ok: bool
    kev_version: str = ""
    epss_date: str = ""

    @property
    def ok(self) -> bool:
        return self.kev_ok and self.epss_ok


# --------------------------------------------------------------------------- policy


def decide(f: Finding, enr: Enrichment, epss_threshold: float) -> Decision:
    """Apply the policy in the module docstring to a single finding."""
    in_kev = f.vuln_id in enr.kev
    score = enr.epss.get(f.vuln_id)

    def d(action: str, reason: str) -> Decision:
        return Decision(f, action, reason, score, in_kev)

    if in_kev:
        return d(BLOCK, "in CISA KEV (known exploited)")
    if not enr.ok and f.fixable and f.rank >= SEVERITY_RANK["HIGH"]:
        return d(BLOCK, f"fixable {f.severity}; EPSS/KEV unavailable, severity-only fallback")
    if f.fixable and f.severity == "CRITICAL":
        return d(BLOCK, "fixable CRITICAL")
    if f.fixable and f.severity == "HIGH":
        if score is None:
            return d(BLOCK, "fixable HIGH with no EPSS score")
        if score >= epss_threshold:
            return d(BLOCK, f"fixable HIGH, EPSS {score:.1%} >= {epss_threshold:.0%}")
        return d(WARN, f"fixable HIGH, EPSS {score:.1%} < {epss_threshold:.0%}")
    if f.rank >= SEVERITY_RANK["HIGH"]:
        return d(WARN, f"{f.severity} with no fix available")
    return d(INFO, f"{f.severity}")


# --------------------------------------------------------------------------- input


def parse_trivy(report: dict) -> tuple[list[Finding], list[Suppressed]]:
    """Extract findings and VEX-suppressed findings from a Trivy JSON report."""
    target = report.get("ArtifactName", "unknown")
    findings: dict[tuple, Finding] = {}
    suppressed: list[Suppressed] = []
    for result in report.get("Results") or []:
        for v in result.get("Vulnerabilities") or []:
            f = Finding(
                target=target,
                vuln_id=v["VulnerabilityID"],
                pkg=v.get("PkgName", ""),
                installed=v.get("InstalledVersion", ""),
                fixed=v.get("FixedVersion", "") or "",
                severity=(v.get("Severity") or "UNKNOWN").upper(),
                title=v.get("Title", "") or "",
            )
            # Trivy can report the same package twice (e.g. two binaries); keep one.
            findings.setdefault((f.target, f.vuln_id, f.pkg, f.installed), f)
        for m in result.get("ExperimentalModifiedFindings") or []:
            inner = m.get("Finding") or {}
            suppressed.append(
                Suppressed(
                    target=target,
                    vuln_id=inner.get("VulnerabilityID", ""),
                    pkg=inner.get("PkgName", ""),
                    status=m.get("Status", ""),
                    statement=m.get("Statement", ""),
                    source=m.get("Source", ""),
                )
            )
    return list(findings.values()), suppressed


# --------------------------------------------------------------------------- enrichment


def _get_json(url: str) -> dict:
    last_err: Exception | None = None
    for attempt in range(3):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
            with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:
                return json.load(resp)
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as err:
            last_err = err
            time.sleep(2**attempt)
    raise RuntimeError(f"GET {url} failed: {last_err}")


def fetch_kev() -> tuple[set[str], str]:
    data = _get_json(KEV_URL)
    return {v["cveID"] for v in data["vulnerabilities"]}, data.get("catalogVersion", "")


def fetch_epss(cves: Iterable[str]) -> tuple[dict[str, float], str]:
    ids = sorted({c for c in cves if c.startswith("CVE-")})
    scores: dict[str, float] = {}
    date = ""
    for i in range(0, len(ids), EPSS_BATCH):
        batch = ids[i : i + EPSS_BATCH]
        query = urllib.parse.urlencode({"cve": ",".join(batch), "limit": EPSS_BATCH})
        data = _get_json(f"{EPSS_URL}?{query}")
        for row in data.get("data", []):
            scores[row["cve"]] = float(row["epss"])
            date = row.get("date", date)
    return scores, date


def load_enrichment(cves: set[str], kev_file: str | None, epss_file: str | None, offline: bool) -> Enrichment:
    enr = Enrichment(kev=set(), epss={}, kev_ok=False, epss_ok=False)
    if kev_file:
        with open(kev_file) as fh:
            enr.kev = {v["cveID"] for v in json.load(fh)["vulnerabilities"]}
        enr.kev_ok, enr.kev_version = True, "file"
    elif not offline:
        try:
            enr.kev, enr.kev_version = fetch_kev()
            enr.kev_ok = True
        except RuntimeError as err:
            print(f"::warning::CISA KEV unavailable: {err}", file=sys.stderr)
    if epss_file:
        with open(epss_file) as fh:
            enr.epss = {k: float(v) for k, v in json.load(fh).items()}
        enr.epss_ok, enr.epss_date = True, "file"
    elif not offline:
        try:
            enr.epss, enr.epss_date = fetch_epss(cves)
            enr.epss_ok = True
        except RuntimeError as err:
            print(f"::warning::EPSS unavailable: {err}", file=sys.stderr)
    return enr


# --------------------------------------------------------------------------- output


def _fmt_epss(score: float | None) -> str:
    return "n/a" if score is None else f"{score:.1%}"


def _row(d: Decision) -> str:
    f = d.finding
    fix = f.fixed or "none"
    kev = "**yes**" if d.kev else "no"
    return (
        f"| `{f.vuln_id}` | `{f.target}` | `{f.pkg}` | {f.installed} → {fix} "
        f"| {f.severity} | {_fmt_epss(d.epss)} | {kev} | {d.reason} |"
    )


def _sort_key(d: Decision) -> tuple:
    return (not d.kev, -(d.epss or 0.0), -d.finding.rank, d.finding.vuln_id)


def render_summary(
    decisions: list[Decision], suppressed: list[Suppressed], enr: Enrichment, epss_threshold: float
) -> str:
    blocks = sorted((d for d in decisions if d.action == BLOCK), key=_sort_key)
    warns = sorted((d for d in decisions if d.action == WARN), key=_sort_key)
    targets = sorted({d.finding.target for d in decisions} | {s.target for s in suppressed})

    header = "| ID | Image | Package | Installed → Fixed | Severity | EPSS | KEV | Reason |\n|---|---|---|---|---|---|---|---|"
    out = [f"## Vulnerability gate: {'❌ blocked' if blocks else '✅ passed'}", ""]
    out.append(
        f"Policy: block CISA KEV entries, fixable CRITICAL, and fixable HIGH with EPSS ≥ {epss_threshold:.0%}. "
        "Everything else is reported."
    )
    if enr.ok:
        out.append(f"Data: KEV catalog `{enr.kev_version}`, EPSS scores `{enr.epss_date}`.")
    else:
        missing = [n for n, ok in (("KEV", enr.kev_ok), ("EPSS", enr.epss_ok)) if not ok]
        out.append(f"> [!WARNING]\n> {' and '.join(missing)} unavailable: falling back to severity-only blocking.")
    out += ["", "| Image | Block | Warn | Info | Suppressed by VEX |", "|---|---|---|---|---|"]
    for t in targets:
        n = {a: sum(1 for d in decisions if d.finding.target == t and d.action == a) for a in (BLOCK, WARN, INFO)}
        s = sum(1 for x in suppressed if x.target == t)
        out.append(f"| `{t}` | {n[BLOCK]} | {n[WARN]} | {n[INFO]} | {s} |")

    if blocks:
        out += ["", f"### Blocking ({len(blocks)})", "", header]
        out += [_row(d) for d in blocks[:MAX_TABLE_ROWS]]
        if len(blocks) > MAX_TABLE_ROWS:
            out.append(f"\n…and {len(blocks) - MAX_TABLE_ROWS} more in the `vuln-gate.json` artifact.")
    if warns:
        out += ["", f"<details><summary>Warnings ({len(warns)}), highest EPSS first</summary>", "", header]
        out += [_row(d) for d in warns[:MAX_TABLE_ROWS]]
        if len(warns) > MAX_TABLE_ROWS:
            out.append(f"\n…and {len(warns) - MAX_TABLE_ROWS} more in the `vuln-gate.json` artifact.")
        out += ["", "</details>"]
    if suppressed:
        out += ["", f"<details><summary>Suppressed by VEX ({len(suppressed)})</summary>", ""]
        out += ["| ID | Image | Package | Status | Justification | Source |", "|---|---|---|---|---|---|"]
        out += [
            f"| `{s.vuln_id}` | `{s.target}` | `{s.pkg}` | {s.status} | {s.statement} | `{s.source}` |"
            for s in suppressed
        ]
        out += ["", "</details>"]
    return "\n".join(out) + "\n"


def write_report(path: str, decisions: list[Decision], suppressed: list[Suppressed], enr: Enrichment) -> None:
    payload = {
        "enrichment": {
            "kev_ok": enr.kev_ok,
            "epss_ok": enr.epss_ok,
            "kev_version": enr.kev_version,
            "epss_date": enr.epss_date,
        },
        "decisions": [
            {**asdict(d.finding), "action": d.action, "reason": d.reason, "epss": d.epss, "kev": d.kev}
            for d in sorted(decisions, key=_sort_key)
        ],
        "suppressed": [asdict(s) for s in suppressed],
    }
    with open(path, "w") as fh:
        json.dump(payload, fh, indent=2)


# --------------------------------------------------------------------------- main


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("reports", nargs="+", help="Trivy JSON reports (trivy image -f json)")
    p.add_argument("--epss-threshold", type=float, default=0.10, help="block fixable HIGH at or above this EPSS (0-1)")
    p.add_argument("--summary", default=os.environ.get("GITHUB_STEP_SUMMARY"), help="markdown summary path")
    p.add_argument("--report", help="write per-finding decisions as JSON")
    p.add_argument("--kev-file", help="use a local KEV catalog JSON instead of downloading")
    p.add_argument("--epss-file", help="use a local {cve: score} JSON instead of the EPSS API")
    p.add_argument("--offline", action="store_true", help="no network; implies severity-only fallback")
    args = p.parse_args(argv)

    if not 0.0 <= args.epss_threshold <= 1.0:
        p.error("--epss-threshold must be between 0 and 1")

    findings: list[Finding] = []
    suppressed: list[Suppressed] = []
    for path in args.reports:
        try:
            with open(path) as fh:
                f, s = parse_trivy(json.load(fh))
        except (OSError, json.JSONDecodeError, KeyError) as err:
            print(f"error: cannot read Trivy report {path}: {err}", file=sys.stderr)
            return 2
        findings += f
        suppressed += s

    enr = load_enrichment({f.vuln_id for f in findings}, args.kev_file, args.epss_file, args.offline)
    decisions = [decide(f, enr, args.epss_threshold) for f in findings]
    blocks = [d for d in decisions if d.action == BLOCK]

    summary = render_summary(decisions, suppressed, enr, args.epss_threshold)
    if args.summary:
        with open(args.summary, "a") as fh:
            fh.write(summary)
    else:
        print(summary)
    if args.report:
        write_report(args.report, decisions, suppressed, enr)

    for d in sorted(blocks, key=_sort_key)[:10]:
        f = d.finding
        print(f"::error title={f.vuln_id} in {f.pkg}::{f.target}: {d.reason} (fix: {f.fixed or 'none'})")
    counts = {a: sum(1 for d in decisions if d.action == a) for a in (BLOCK, WARN, INFO)}
    print(
        f"vuln-gate: {counts[BLOCK]} block, {counts[WARN]} warn, {counts[INFO]} info, "
        f"{len(suppressed)} suppressed by VEX -> {'FAIL' if blocks else 'PASS'}"
    )
    return 1 if blocks else 0


if __name__ == "__main__":
    sys.exit(main())
