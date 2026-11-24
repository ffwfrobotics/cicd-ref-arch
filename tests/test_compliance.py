"""External findings (tools/external.py), the gate with them, and the OSCAL self-assessment
(tools/oscal.py). Offline: endpoint checks run against a local HTTPS server."""
import datetime as dt
import http.server
import json
import shutil
import ssl
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))

import cicd  # noqa: E402
import external  # noqa: E402
import oscal  # noqa: E402
import security  # noqa: E402

TODAY = dt.date(2026, 11, 20)
SBOM = {"components": [
    {"name": "gunicorn", "version": "23.0.0", "purl": "pkg:pypi/gunicorn@23.0.0"},
    {"name": "Werkzeug", "version": "3.1.9", "purl": "pkg:pypi/werkzeug@3.1.9"},
    {"name": "openssl", "version": "3.5.1-r0", "purl": "pkg:apk/wolfi/openssl@3.5.1-r0"}]}


class Versions(unittest.TestCase):
    def test_compare(self):
        self.assertTrue(external.affected("23.0.0", "<25"))
        self.assertFalse(external.affected("25.0", "<25"))
        self.assertTrue(external.affected("2.1", ">=2.0,<2.3"))
        self.assertFalse(external.affected("2.3.0", ">=2.0,<2.3"))
        self.assertTrue(external.affected("3.0.0rc1", "<3.0.0"))      # a pre-release comes before the release
        self.assertTrue(external.affected("1.2", "==1.2.0"))
        self.assertTrue(external.affected("v1.10.0", ">1.9.9"))


class Checks(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        (self.tmp / "sbom.json").write_text(json.dumps(SBOM))
        self.ctx = {"packages": external.sbom_packages(self.tmp / "sbom.json"), "app": "demo",
                    "raw_findings": [{"rule": "python.flask.debug", "tool": "opengrep", "location": "app.py:9",
                                      "suppressed": {"by": "ignore (app)", "reason": "dev said so"}}]}

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def run_one(self, entry):
        return external.external_findings([entry], [], self.ctx, TODAY)

    def test_package_fails_then_passes(self):
        e = {"id": "A", "check": {"type": "package", "name": "gunicorn", "ecosystem": "pypi", "affected": "<25"}}
        f, t = self.run_one(e)
        self.assertEqual(t[0]["result"], "fail")
        self.assertEqual(f[0]["location"], "pkg:pypi/gunicorn@23.0.0")
        self.assertEqual(f[0]["rule"], "external/A")
        e["check"]["affected"] = "<23"
        f, t = self.run_one(e)
        self.assertEqual((f, t[0]["result"]), ([], "pass"))

    def test_package_names_normalise(self):
        e = {"id": "W", "check": {"type": "package", "name": "werkzeug", "affected": "<=3.1.9"}}
        self.assertEqual(self.run_one(e)[1][0]["result"], "fail")

    def test_rule_ignores_the_developers_suppression(self):
        f, t = self.run_one({"id": "R", "check": {"type": "rule", "rule": "python.flask.debug"}})
        self.assertEqual(t[0]["result"], "fail")

    def test_manual_accepted_closed(self):
        self.assertEqual(self.run_one({"id": "M"})[1][0]["result"], "fail")
        f, t = self.run_one({"id": "M", "status": "accepted",
                             "accepted": {"by": "sec", "reason": "compensating control", "expires": "2027-01-01"}})
        self.assertEqual(t[0]["result"], "accepted")
        self.assertIn("risk accepted", f[0]["suppressed"]["by"])
        f, t = self.run_one({"id": "M", "status": "accepted", "accepted": {"by": "sec", "reason": "x", "expires": "2026-01-01"}})
        self.assertEqual(t[0]["result"], "fail")               # an expired acceptance is no acceptance
        self.assertEqual(self.run_one({"id": "M", "status": "closed"}), ([], []))

    def test_advisory_matches_the_sbom(self):
        adv = {"id": "ADV-1", "title": "made up", "severity": "critical", "announced": "2026-11-20T00:00:00Z",
               "package": {"name": "openssl", "ecosystem": "apk", "affected": "<3.5.2", "fixed": "3.5.2"}}
        f, t = external.external_findings([], [adv], self.ctx, TODAY)
        self.assertEqual([(x["category"], x["tool"], x["fix_state"], x["fixed_in"]) for x in f],
                         [("vuln", "advisory", "fixed", ["3.5.2"])])
        adv["package"]["affected"] = "<3.5.0"
        self.assertEqual(external.external_findings([], [adv], self.ctx, TODAY), ([], []))

    def test_the_developers_ignore_cannot_suppress_an_external_finding(self):
        f, _ = self.run_one({"id": "A", "severity": "high", "check": {"type": "package", "name": "gunicorn", "affected": "<25"}})
        pol = {"environments": {"prod": {"mode": "enforce"}}, "categories": {"external": {"fail_at": "low"}},
               "ignore": [{"rule": "external/*", "reason": "no", "expires": "2099-01-01", "owner": "app"}]}
        res = security.gate(f, pol, "prod", [], [], today=TODAY)
        self.assertEqual((res["status"], res["findings"][0]["outcome"]), ("fail", "fail"))


class _Handler(http.server.BaseHTTPRequestHandler):
    hsts = False

    def do_GET(self):
        self.send_response(200)
        if _Handler.hsts:
            self.send_header("Strict-Transport-Security", "max-age=31536000")
        self.send_header("X-Seen-Host", self.headers.get("Host", ""))
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *a):
        pass


@unittest.skipUnless(shutil.which("openssl"), "needs openssl to make a test certificate")
class Endpoint(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp())
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=test",
                        "-keyout", str(cls.tmp / "k.pem"), "-out", str(cls.tmp / "c.pem")], check=True, capture_output=True)
        cls.srv = http.server.HTTPServer(("127.0.0.1", 0), _Handler)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cls.tmp / "c.pem", cls.tmp / "k.pem")
        cls.srv.socket = ctx.wrap_socket(cls.srv.socket, server_side=True)
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        shutil.rmtree(cls.tmp)

    def test_header_through_the_gateway(self):
        ctx = {"host": "demo.example.test", "via": f"127.0.0.1:{self.srv.server_address[1]}"}
        e = {"id": "H", "check": {"type": "endpoint", "header": "Strict-Transport-Security"}}
        _Handler.hsts = False
        self.assertEqual(external.evaluate(e, ctx)[0], "fail")
        _Handler.hsts = True
        res, detail = external.evaluate(e, ctx)
        self.assertEqual(res, "pass", detail)
        status, headers = external.probe("demo.example.test", "/", ctx["via"])
        self.assertEqual(headers["x-seen-host"], "demo.example.test")

    def test_not_deployed_yet_is_unknown_and_still_open(self):
        e = {"id": "H", "check": {"type": "endpoint", "header": "Strict-Transport-Security"}}
        f, t = external.external_findings([e], [], {"host": "x", "skip_endpoints": "checked after deploy"}, TODAY)
        self.assertEqual((t[0]["result"], f[0]["unknown"]), ("fail", True))


def mini_catalog():
    obj = lambda i, prose: {"id": i, "name": "assessment-objective", "prose": prose}  # noqa: E731
    return {"catalog": {"groups": [{"id": "ra", "title": "RA", "controls": [{
        "id": "ra-5", "title": "Vulnerability Monitoring and Scanning", "parts": [
            {"id": "ra-5_obj", "name": "assessment-objective", "parts": [
                obj("ra-5_obj.a-2", "scanned {{ insert: param, ra-05_odp.02 }}"), obj("ra-5_obj.d", "remediated"),
                obj("ra-5_obj.e", "shared"), obj("ra-5_obj.f", "tools update")]}]}]}]}}


class Assessment(unittest.TestCase):
    def setUp(self):
        self.ev = Path(tempfile.mkdtemp())
        rec = {"commit": "a" * 40, "image": "r/app@sha256:1",
               "scans": {"image": {"tools": {"grype": "0.1", "grype-db": "2026-11-19T00:00:00Z"}}},
               "gate": {"status": "warn", "env": "dev", "mode": "report"},
               "findings": [{"category": "vuln", "rule": "CVE-1", "outcome": "fail"}]}
        (self.ev / "security.json").write_text(json.dumps(rec))
        self.objs = oscal.objectives_for(mini_catalog(), ["ra-5"])
        self.stmts = oscal.merged([
            {"layer": "platform", "component": "p", "objectives": {
                "ra-5_obj.a-2": {"statement": "scanned", "evidence": [{"kind": "scan", "tool": "grype"}]},
                "ra-5_obj.d": {"statement": "fixed", "evidence": [{"kind": "findings", "category": "vuln"}]},
                "ra-5_obj.e": {"statement": "released", "evidence": [{"kind": "release", "within_days": 30}]}}},
            {"layer": "sysadmin", "component": "s", "objectives": {
                "ra-5_obj.a-2": {"statement": "we look too", "evidence": [
                    {"kind": "scan", "tool": "grype"}, {"kind": "attested", "name": "x", "by": "j", "at": "2026-11-20", "expires": "2027-01-01"}]}}}])

    def tearDown(self):
        shutil.rmtree(self.ev)

    def test_layers_coverage_and_blockers(self):
        ev = oscal.Evidence(self.ev, None, "app", today=dt.datetime(2026, 11, 20, tzinfo=dt.timezone.utc))
        ar, s = oscal.assess(self.objs, self.stmts, ev, {"app": "app", "env": "dev", "commit": "a" * 40})
        rows = {r["id"]: r for r in s["objectives"]}
        self.assertEqual(rows["ra-5_obj.a-2"]["layer"], "sysadmin")          # a later layer replaces an earlier one
        self.assertEqual(rows["ra-5_obj.a-2"]["coverage"], "manual")
        self.assertEqual(rows["ra-5_obj.d"]["state"], "not-satisfied")
        self.assertEqual(rows["ra-5_obj.f"]["coverage"], "uncovered")
        self.assertIn("[ra-05_odp.02]", rows["ra-5_obj.a-2"]["objective"])
        self.assertEqual(s["coverage"], {"manual": 1, "automated": 2, "uncovered": 1})
        blockers = cicd.assessment_blockers(s)
        self.assertEqual(len(blockers), 1)                                   # the vuln; not the release, not the uncovered
        self.assertTrue(blockers[0].startswith("ra-5_obj.d"))
        meta = {p["name"]: p["value"] for p in ar["assessment-results"]["metadata"]["props"]}
        self.assertEqual(meta["assessment-kind"], "self-assessment")
        f = ar["assessment-results"]["results"][0]["findings"]
        self.assertEqual({x["target"]["target-id"] for x in f}, {o["id"] for o in self.objs})

    def test_the_instance_layer_comes_after_the_platform(self):
        d = self.ev
        (d / "catalog.json").write_text(json.dumps(mini_catalog()))
        (d / "profile.json").write_text(json.dumps({"profile": {"imports": [{"include-controls": [{"with-ids": ["ra-5"]}]}]}}))
        (d / "platform.yaml").write_text("component: p\nobjectives:\n  ra-5_obj.d: {statement: p, evidence: [{kind: gate}]}\n")
        (d / "instance.yaml").write_text("component: i\nobjectives:\n  ra-5_obj.d:\n    statement: i\n    evidence:\n"
                                         "    - {kind: attested, name: x, by: j, at: 2026-11-20, expires: 2099-01-01}\n")
        out = d / "out"
        out.mkdir()
        subprocess.run([sys.executable, str(ROOT / "tools/oscal.py"), "assess", "--catalog", str(d / "catalog.json"),
                        "--profile", str(d / "profile.json"), "--platform", str(d / "platform.yaml"),
                        "--instance-layer", str(d / "instance.yaml"), "--evidence", str(d), "--app", "app",
                        "--env", "dev", "--out", str(out)], check=True, capture_output=True)
        s = json.loads((out / "assessment-summary.json").read_text())
        rows = {r["id"]: r for r in s["objectives"]}
        self.assertEqual(rows["ra-5_obj.d"]["layer"], "instance")
        self.assertEqual([L["layer"] for L in s["layers"]], ["platform", "instance"])

    def test_the_product_attests_nothing(self):
        # an attestation is about one instance's forge or hosts: it belongs in that instance's oscal/instance.yaml
        import yaml
        plat = yaml.safe_load((ROOT / "oscal/platform.yaml").read_text())
        kinds = {e["kind"] for o in plat["objectives"].values() for e in o.get("evidence") or []}
        self.assertNotIn("attested", kinds)


if __name__ == "__main__":
    unittest.main()
