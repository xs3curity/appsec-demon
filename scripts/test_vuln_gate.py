"""Unit tests for vuln_gate.py. Run: python3 -m unittest discover -s scripts -v"""

import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from datetime import date, timedelta
from io import StringIO

import vuln_gate as g


def finding(vid="CVE-2026-0001", sev="HIGH", fixed="1.2.3", target="img:ci", pkg="libfoo"):
    return g.Finding(target, vid, pkg, "1.0.0", fixed, sev, "title")


def enrichment(kev=(), epss=None, ok=True):
    return g.Enrichment(kev=set(kev), epss=dict(epss or {}), kev_ok=ok, epss_ok=ok, kev_version="v", epss_date="d")


class DecideTest(unittest.TestCase):
    T = 0.10

    def assertAction(self, f, enr, action, reason_part):
        d = g.decide(f, enr, self.T)
        self.assertEqual(d.action, action, d.reason)
        self.assertIn(reason_part, d.reason)

    def test_kev_blocks_at_any_severity_even_without_fix(self):
        self.assertAction(finding(sev="LOW", fixed=""), enrichment(kev=["CVE-2026-0001"]), g.BLOCK, "KEV")

    def test_fixable_critical_blocks_even_with_low_epss(self):
        self.assertAction(finding(sev="CRITICAL"), enrichment(epss={"CVE-2026-0001": 0.0001}), g.BLOCK, "CRITICAL")

    def test_fixable_high_blocks_at_threshold(self):
        self.assertAction(finding(), enrichment(epss={"CVE-2026-0001": 0.10}), g.BLOCK, ">=")

    def test_fixable_high_warns_below_threshold(self):
        self.assertAction(finding(), enrichment(epss={"CVE-2026-0001": 0.0999}), g.WARN, "<")

    def test_fixable_high_without_epss_score_blocks(self):
        # GHSA-only IDs and brand-new CVEs have no EPSS score yet: do not assume they are safe.
        self.assertAction(finding(vid="GHSA-xxxx-yyyy-zzzz"), enrichment(), g.BLOCK, "no EPSS")

    def test_unfixed_high_and_critical_block_without_acceptance(self):
        for sev in ("HIGH", "CRITICAL"):
            self.assertAction(finding(sev=sev, fixed=""), enrichment(), g.BLOCK, "no risk acceptance")

    def test_medium_not_in_kev_is_info(self):
        self.assertAction(finding(sev="MEDIUM"), enrichment(), g.INFO, "MEDIUM")

    def test_fallback_blocks_fixable_high_when_enrichment_failed(self):
        enr = enrichment(epss={"CVE-2026-0001": 0.0001}, ok=False)
        self.assertAction(finding(), enr, g.BLOCK, "fallback")

    def test_fallback_still_uses_kev_hits_it_has(self):
        enr = g.Enrichment(kev={"CVE-2026-0001"}, epss={}, kev_ok=True, epss_ok=False)
        self.assertAction(finding(sev="MEDIUM", fixed=""), enr, g.BLOCK, "KEV")

    def test_fallback_unfixed_still_needs_acceptance(self):
        self.assertAction(finding(fixed=""), enrichment(ok=False), g.BLOCK, "no risk acceptance")


TODAY = date(2026, 11, 27)


def acceptance(vid="CVE-2026-0001", pkgs=("libfoo",), expires=TODAY + timedelta(days=30)):
    return g.Acceptance(vid, frozenset(pkgs), "reviewed: not reachable", expires)


class AcceptanceDecideTest(unittest.TestCase):
    def decide(self, f, acc, enr=None):
        return g.decide(f, enr or enrichment(), 0.10, acc, TODAY)

    def test_valid_acceptance_downgrades_unfixed_to_warn(self):
        d = self.decide(finding(sev="CRITICAL", fixed=""), acceptance())
        self.assertEqual((d.action, d.accepted_until), (g.WARN, "2026-12-27"))

    def test_acceptance_valid_on_expiry_day(self):
        self.assertEqual(self.decide(finding(fixed=""), acceptance(expires=TODAY)).action, g.WARN)

    def test_expired_acceptance_blocks(self):
        d = self.decide(finding(fixed=""), acceptance(expires=TODAY - timedelta(days=1)))
        self.assertEqual(d.action, g.BLOCK)
        self.assertIn("expired", d.reason)

    def test_acceptance_never_overrides_kev(self):
        d = self.decide(finding(fixed=""), acceptance(), enrichment(kev=["CVE-2026-0001"]))
        self.assertEqual(d.action, g.BLOCK)
        self.assertIn("KEV", d.reason)

    def test_acceptance_never_overrides_fixable(self):
        self.assertEqual(self.decide(finding(sev="CRITICAL"), acceptance()).action, g.BLOCK)

    def test_covers_requires_matching_package(self):
        self.assertIsNone(g.find_acceptance(finding(pkg="libbar"), [acceptance()]))
        self.assertIsNotNone(g.find_acceptance(finding(), [acceptance()]))


class LoadAcceptancesTest(unittest.TestCase):
    def load(self, entries):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
            json.dump({"acceptances": entries}, fh)
        self.addCleanup(os.unlink, fh.name)
        return g.load_acceptances(fh.name, TODAY)

    def entry(self, **kw):
        e = {"id": "CVE-1", "packages": ["p"], "reason": "no fix upstream; never invoked", "expires": "2027-01-15"}
        e.update(kw)
        return e

    def test_loads_valid_entry(self):
        (a,) = self.load([self.entry()])
        self.assertEqual((a.vuln_id, a.packages, a.expires), ("CVE-1", frozenset({"p"}), date(2027, 1, 15)))

    def test_rejects_invalid_entries(self):
        bad = {
            "too far": self.entry(expires="2027-03-01"),
            "bad date": self.entry(expires="soon"),
            "no reason": self.entry(reason="ok"),
            "no packages": self.entry(packages=[]),
            "no id": self.entry(id=""),
        }
        for name, e in bad.items():
            with self.subTest(name), self.assertRaises(ValueError):
                self.load([e])

    def test_rejects_duplicates(self):
        with self.assertRaises(ValueError):
            self.load([self.entry(), self.entry(packages=["q", "p"])])

    def test_expired_entries_still_load(self):
        # So the gate can say "expired" instead of silently treating it as missing.
        (a,) = self.load([self.entry(expires="2026-01-01")])
        self.assertLess(a.expires, TODAY)


class ParseTrivyTest(unittest.TestCase):
    REPORT = {
        "ArtifactName": "appsec_demon_app:ci",
        "Results": [
            {
                "Target": "debian",
                "Vulnerabilities": [
                    {"VulnerabilityID": "CVE-1", "PkgName": "libz", "InstalledVersion": "1", "FixedVersion": "2", "Severity": "high"},
                    {"VulnerabilityID": "CVE-1", "PkgName": "libz", "InstalledVersion": "1", "FixedVersion": "2", "Severity": "HIGH"},
                    {"VulnerabilityID": "CVE-2", "PkgName": "libc", "InstalledVersion": "1", "Severity": "LOW"},
                ],
            },
            {"Target": "python", "Vulnerabilities": None},
            {
                "Target": "python-pkgs",
                "ExperimentalModifiedFindings": [
                    {
                        "Type": "vulnerability",
                        "Status": "not_affected",
                        "Statement": "vulnerable_code_not_in_execute_path",
                        "Source": "security/vex/appsec-demon.openvex.json",
                        "Finding": {"VulnerabilityID": "CVE-3", "PkgName": "werkzeug"},
                    }
                ],
            },
        ],
    }

    def test_parses_dedupes_and_normalises(self):
        findings, suppressed = g.parse_trivy(self.REPORT)
        self.assertEqual(sorted(f.vuln_id for f in findings), ["CVE-1", "CVE-2"])
        cve1 = next(f for f in findings if f.vuln_id == "CVE-1")
        self.assertEqual((cve1.severity, cve1.fixable, cve1.target), ("HIGH", True, "appsec_demon_app:ci"))
        self.assertFalse(next(f for f in findings if f.vuln_id == "CVE-2").fixable)

    def test_collects_vex_suppressed(self):
        _, suppressed = g.parse_trivy(self.REPORT)
        self.assertEqual(len(suppressed), 1)
        self.assertEqual((suppressed[0].vuln_id, suppressed[0].status), ("CVE-3", "not_affected"))

    def test_empty_report(self):
        self.assertEqual(g.parse_trivy({"ArtifactName": "x"}), ([], []))


class MainTest(unittest.TestCase):
    def run_main(self, vulns, kev=(), epss=None, extra=()):
        with tempfile.TemporaryDirectory() as d:
            paths = {}
            for name, data in (
                ("trivy", {"ArtifactName": "img:ci", "Results": [{"Vulnerabilities": vulns}]}),
                ("kev", {"vulnerabilities": [{"cveID": c} for c in kev]}),
                ("epss", epss or {}),
            ):
                paths[name] = os.path.join(d, f"{name}.json")
                with open(paths[name], "w") as fh:
                    json.dump(data, fh)
            summary, report = os.path.join(d, "summary.md"), os.path.join(d, "report.json")
            args = [paths["trivy"], "--kev-file", paths["kev"], "--epss-file", paths["epss"],
                    "--summary", summary, "--report", report, *extra]
            with redirect_stdout(StringIO()) as out:
                code = g.main(args)
            with open(summary) as fh, open(report) as rh:
                return code, fh.read(), json.load(rh), out.getvalue()

    def vuln(self, vid, sev, fixed="2"):
        return {"VulnerabilityID": vid, "PkgName": "p", "InstalledVersion": "1", "FixedVersion": fixed, "Severity": sev}

    def test_pass_when_only_low_epss_high(self):
        code, summary, report, out = self.run_main([self.vuln("CVE-9", "HIGH")], epss={"CVE-9": 0.01})
        self.assertEqual(code, 0)
        self.assertIn("✅ passed", summary)
        self.assertEqual(report["decisions"][0]["action"], "warn")
        self.assertIn("PASS", out)

    def test_fail_on_kev_and_emits_annotation(self):
        code, summary, report, out = self.run_main([self.vuln("CVE-9", "MEDIUM", fixed="")], kev=["CVE-9"])
        self.assertEqual(code, 1)
        self.assertIn("❌ blocked", summary)
        self.assertIn("::error title=CVE-9", out)

    def test_threshold_flag(self):
        code, *_ = self.run_main([self.vuln("CVE-9", "HIGH")], epss={"CVE-9": 0.3}, extra=["--epss-threshold", "0.5"])
        self.assertEqual(code, 0)

    def test_offline_falls_back_to_severity(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "t.json")
            with open(p, "w") as fh:
                json.dump({"ArtifactName": "i", "Results": [{"Vulnerabilities": [self.vuln("CVE-9", "HIGH")]}]}, fh)
            with redirect_stdout(StringIO()) as out:
                code = g.main([p, "--offline", "--summary", os.path.join(d, "s.md")])
            self.assertEqual(code, 1)
            self.assertIn("FAIL", out.getvalue())

    def test_bad_input_returns_2(self):
        with redirect_stdout(StringIO()), redirect_stderr(StringIO()):
            self.assertEqual(g.main(["/nonexistent.json", "--offline"]), 2)

    def acceptances_file(self, d, entries):
        p = os.path.join(d, "acc.json")
        with open(p, "w") as fh:
            json.dump({"acceptances": entries}, fh)
        return p

    def test_unfixed_high_passes_only_with_acceptance(self):
        soon = (g.utc_today() + timedelta(days=60)).isoformat()
        vulns = [self.vuln("CVE-9", "HIGH", fixed="")]
        code, *_ = self.run_main(vulns)
        self.assertEqual(code, 1)
        with tempfile.TemporaryDirectory() as d:
            acc = self.acceptances_file(d, [
                {"id": "CVE-9", "packages": ["p"], "reason": "no fix upstream; not reachable", "expires": soon},
                {"id": "CVE-8", "packages": ["p"], "reason": "no fix upstream; not reachable", "expires": soon},
            ])
            code, summary, report, out = self.run_main(vulns, extra=["--acceptances", acc])
        self.assertEqual(code, 0)
        self.assertEqual(report["decisions"][0]["accepted_until"], soon)
        self.assertIn("Risk acceptances (2)", summary)
        self.assertIn("Unused risk acceptance CVE-8", out)

    def test_invalid_acceptance_file_returns_2(self):
        with tempfile.TemporaryDirectory() as d:
            acc = self.acceptances_file(d, [{"id": "CVE-9"}])
            p = os.path.join(d, "t.json")
            with open(p, "w") as fh:
                json.dump({"ArtifactName": "i", "Results": []}, fh)
            with redirect_stdout(StringIO()), redirect_stderr(StringIO()):
                self.assertEqual(g.main([p, "--offline", "--acceptances", acc]), 2)


if __name__ == "__main__":
    unittest.main()
