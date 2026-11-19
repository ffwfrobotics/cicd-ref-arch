"""Unit tests for tools/security.py: parsers, policy merging, the gate. Run: python3 -m unittest -v"""
import datetime as dt
import json
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "tools"))
import security  # noqa: E402

TODAY = dt.date(2026, 11, 19)


def f(category, rule, severity="high", location="app.py:1", **kw):
    return security.finding(category, "t", rule, severity, location, "m", **kw)


class Policy(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())

    def app_policy(self, text):
        p = self.dir / "policy.yaml"
        p.write_text(text)
        return p

    def test_app_may_tighten_not_loosen(self):
        pol, notes = security.load_policy(REPO / "security/policy.yaml", self.app_policy(
            "environments: {dev: {mode: enforce}, prod: {mode: report}}\n"
            "categories: {vuln: {fail_at: medium}, sast: {fail_at: critical}}\n"))
        self.assertEqual(pol["environments"]["dev"]["mode"], "enforce")
        self.assertEqual(pol["environments"]["prod"]["mode"], "enforce")
        self.assertEqual(pol["categories"]["vuln"]["fail_at"], "medium")
        self.assertEqual(pol["categories"]["sast"]["fail_at"], "high")
        self.assertEqual(len(notes), 2)

    def test_app_ignore_needs_reason_and_expiry(self):
        pol, notes = security.load_policy(REPO / "security/policy.yaml", self.app_policy(
            "ignore:\n- {rule: CKV_X, reason: because}\n- {rule: CKV_Y, reason: because, expires: 2026-12-01}\n"))
        rules = [i["rule"] for i in pol["ignore"]]
        self.assertIn("CKV_Y", rules)
        self.assertNotIn("CKV_X", rules)
        self.assertTrue(any("expires" in n for n in notes))


class Gate(unittest.TestCase):
    def setUp(self):
        self.pol, _ = security.load_policy(REPO / "security/policy.yaml", None)

    def run_gate(self, findings, env="prod", expected=(), seen=()):
        return security.gate(findings, self.pol, env, list(expected), list(seen), today=TODAY)

    def test_report_mode_warns_enforce_fails(self):
        fs = [f("sast", "ffwf.python.eval")]
        self.assertEqual(self.run_gate(fs, "dev")["status"], "warn")
        self.assertEqual(self.run_gate(fs, "prod")["status"], "fail")

    def test_secrets_block_even_in_report_mode(self):
        self.assertEqual(self.run_gate([f("secrets", "generic-api-key")], "dev")["status"], "fail")

    def test_below_threshold_passes(self):
        self.assertEqual(self.run_gate([f("sast", "x", "medium")])["status"], "pass")

    def test_vuln_without_fix_does_not_gate(self):
        r = self.run_gate([f("vuln", "CVE-1", fix_state="not-fixed"), f("vuln", "CVE-2", "low", fix_state="fixed")])
        self.assertEqual(r["status"], "pass")
        self.assertEqual(r["counts"], {"no-fix-available": 1, "below-threshold": 1})
        self.assertEqual(self.run_gate([f("vuln", "CVE-3", "critical", fix_state="fixed")])["status"], "fail")

    def test_platform_ignore(self):
        r = self.run_gate([f("config", "CKV_K8S_43")])
        self.assertEqual(r["status"], "pass")
        self.assertEqual(r["findings"][0]["suppressed"]["by"], "ignore (platform)")

    def test_expired_ignore_gates_again(self):
        self.pol["ignore"].append({"rule": "CKV_K8S_11", "reason": "r", "expires": "2026-11-01", "owner": "app"})
        r = self.run_gate([f("config", "CKV_K8S_11")])
        self.assertEqual(r["status"], "fail")
        self.assertIn("expired_ignore", r["findings"][0])
        self.pol["ignore"].append({"rule": "CKV_K8S_11", "reason": "r", "expires": "2026-12-31", "owner": "app"})
        self.assertEqual(self.run_gate([f("config", "CKV_K8S_11")])["status"], "pass")

    def test_ignore_path_glob(self):
        self.pol["ignore"].append({"rule": "generic-api-key", "path": "tests/fixtures/*", "reason": "r",
                                   "expires": "2027-01-01", "owner": "app"})
        self.assertEqual(self.run_gate([f("secrets", "generic-api-key", location="tests/fixtures/k.txt:3")], "dev")["status"], "pass")
        self.assertEqual(self.run_gate([f("secrets", "generic-api-key", location="app.py:3")], "dev")["status"], "fail")

    def test_vex_suppressed_stays_suppressed(self):
        x = f("vuln", "CVE-9", "critical", fix_state="fixed", suppressed={"by": "vex", "reason": "not reachable"})
        self.assertEqual(self.run_gate([x])["status"], "pass")

    def test_missing_tool_fails_in_enforce(self):
        r = self.run_gate([], "prod", expected=["grype"], seen=[])
        self.assertEqual(r["status"], "fail")
        self.assertEqual(r["findings"][0]["category"], "tooling")
        self.assertEqual(self.run_gate([], "dev", expected=["grype"], seen=[])["status"], "warn")


class Parsers(unittest.TestCase):
    def tmp(self, obj):
        p = Path(tempfile.mkdtemp()) / "x.json"
        p.write_text(json.dumps(obj))
        return p

    def test_grype_matches_and_vex_ignored(self):
        m = lambda cve: {"vulnerability": {"id": cve, "severity": "High", "fix": {"state": "fixed", "versions": ["2.0"]}},
                         "artifact": {"name": "werkzeug", "version": "1.0", "type": "python", "purl": "pkg:pypi/werkzeug@1.0"}}
        ign = dict(m("CVE-B"), appliedIgnoreRules=[{"vex-justification": "vulnerable_code_not_in_execute_path"}])
        fs = security.parse_grype(self.tmp({"matches": [m("CVE-A")], "ignoredMatches": [ign]}))
        self.assertEqual([x["rule"] for x in fs], ["CVE-A", "CVE-B"])
        self.assertEqual(fs[0]["fixed_in"], ["2.0"])
        self.assertEqual(fs[1]["suppressed"]["by"], "vex")

    def test_gitleaks_fingerprint(self):
        fs = security.parse_gitleaks(self.tmp([{"RuleID": "generic-api-key", "File": "a.py", "StartLine": 4,
                                                "Description": "Generic API Key"}]))
        self.assertEqual(fs[0]["fingerprint"], "a.py:generic-api-key:4")
        self.assertEqual(fs[0]["category"], "secrets")

    def test_opengrep_rule_id_and_level(self):
        sarif = {"runs": [{"tool": {"driver": {"rules": [{"id": "x.security.rules.ffwf.python.eval",
                                                          "defaultConfiguration": {"level": "error"}}]}},
                           "results": [{"ruleId": "x.security.rules.ffwf.python.eval", "message": {"text": "eval"},
                                        "locations": [{"physicalLocation": {"artifactLocation": {"uri": "app.py"},
                                                                            "region": {"startLine": 7}}}]}]}]}
        fs = security.parse_opengrep(self.tmp(sarif))
        self.assertEqual((fs[0]["rule"], fs[0]["severity"], fs[0]["location"]), ("ffwf.python.eval", "high", "app.py:7"))


if __name__ == "__main__":
    unittest.main()
