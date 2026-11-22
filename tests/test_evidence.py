"""Unit tests for tools/evidence.py: scans as releases on the evidence repo. Run: python3 -m unittest -v"""
import datetime as dt
import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "tools"))
import cicd  # noqa: E402
import evidence  # noqa: E402
import yaml  # noqa: E402

DIGEST = "sha256:" + "a" * 64
POL = {"repo": "cicd/evidence", "keep": 1, "days": None}


class FakeForge:
    """Releases and assets in memory, as tools/evidence.Forge sees them."""
    base = "https://forge.test"

    def __init__(self):
        self.rels: dict[str, dict] = {}
        self.blobs: dict[str, bytes] = {}
        self.uploads = 0
        self.clock = dt.datetime(2026, 11, 22, tzinfo=dt.timezone.utc)

    def release(self, repo, tag):
        return self.rels.get(tag)

    def create_release(self, repo, tag, body):
        self.clock += dt.timedelta(minutes=1)
        r = {"id": len(self.rels) + 1, "tag_name": tag, "created_at": self.clock.isoformat().replace("+00:00", "Z"),
             "html_url": f"{self.base}/{repo}/releases/tag/{tag}", "assets": []}
        self.rels[tag] = r
        return r

    def upload(self, repo, release_id, name, data):
        self.uploads += 1
        tag = next(t for t, r in self.rels.items() if r["id"] == release_id)
        url = f"{self.base}/{repo}/releases/download/{tag}/{name}"
        self.blobs[url] = data
        a = {"name": name, "size": len(data), "browser_download_url": url}
        self.rels[tag]["assets"].append(a)
        return a

    def download(self, url):
        return self.blobs[url]

    def releases(self, repo):
        return list(self.rels.values())

    def delete(self, repo, tag):
        self.rels.pop(tag, None)


class Publish(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp()) / "evidence"
        self.forge = FakeForge()
        self.d.mkdir()
        (self.d / "sbom.cdx.json").write_text('{"components": []}')
        (self.d / "security.json").write_text('{"gate": {"status": "pass"}}')
        (self.d / "assessment-summary.json").write_text('{"counts": {}}')

    def test_scans_move_and_small_files_stay(self):
        m = evidence.publish(self.d, "c1", "app", "dev", POL, self.forge, {"image": "x"})
        self.assertEqual(sorted(p.name for p in self.d.iterdir()), ["assessment-summary.json", "evidence.json"])
        self.assertEqual(sorted(m["files"]), ["sbom.cdx.json", "security.json"])
        self.assertTrue(m["tag"].startswith("c1/app/dev/"))
        self.assertEqual(json.loads((self.d / "evidence.json").read_text()), m)

    def test_same_files_same_release(self):
        m1 = evidence.publish(self.d, "c1", "app", "dev", POL, self.forge)
        evidence.fetch(self.d, self.forge)
        m2 = evidence.publish(self.d, "c1", "app", "dev", POL, self.forge)
        self.assertEqual(m1["tag"], m2["tag"])
        self.assertEqual(len(self.forge.rels), 1)
        self.assertEqual(self.forge.uploads, 2)     # a retried job doesn't upload again

    def test_previous_files_are_carried_into_a_new_version(self):
        m1 = evidence.publish(self.d, "c1", "app", "prod", POL, self.forge)
        (self.d / "security.json").write_text('{"gate": {"status": "fail"}}')    # a re-scan replaces one file
        m2 = evidence.publish(self.d, "c1", "app", "prod", POL, self.forge)
        self.assertNotEqual(m1["tag"], m2["tag"])
        self.assertEqual(sorted(m2["files"]), ["sbom.cdx.json", "security.json"])
        self.assertEqual(m2["files"]["sbom.cdx.json"]["sha256"], m1["files"]["sbom.cdx.json"]["sha256"])

    def test_fetch_refuses_altered_files(self):
        m = evidence.publish(self.d, "c1", "app", "dev", POL, self.forge)
        self.forge.blobs[m["files"]["sbom.cdx.json"]["url"]] = b"{}"
        with self.assertRaisesRegex(RuntimeError, "altered"):
            evidence.fetch(self.d, self.forge, ["sbom.cdx.json"])

    def test_fetch_by_name(self):
        evidence.publish(self.d, "c1", "app", "dev", POL, self.forge)
        self.assertEqual(evidence.fetch(self.d, self.forge, ["sbom.cdx.json"]), ["sbom.cdx.json"])
        self.assertFalse((self.d / "security.json").exists())


class Retention(unittest.TestCase):
    NOW = dt.datetime(2026, 11, 22, 12, tzinfo=dt.timezone.utc)

    def rels(self, env, ages_days):
        return [{"tag_name": f"c1/app/{env}/v{i}", "created_at": (self.NOW - dt.timedelta(days=a)).isoformat()}
                for i, a in enumerate(ages_days)]

    def doomed(self, rels, pol, refs=(), live=(("c1", "app", "dev"),)):
        return sorted(evidence.doomed(rels, set(refs), set(live), lambda c, a: pol, self.NOW))

    def test_latest_only(self):
        self.assertEqual(self.doomed(self.rels("dev", [0, 1, 2]), {"keep": 1}), ["c1/app/dev/v1", "c1/app/dev/v2"])

    def test_last_three(self):
        self.assertEqual(self.doomed(self.rels("dev", [0, 1, 2, 3, 4]), {"keep": 3}), ["c1/app/dev/v3", "c1/app/dev/v4"])

    def test_days(self):
        self.assertEqual(self.doomed(self.rels("dev", [0, 10, 100]), {"keep": 0, "days": 90}), ["c1/app/dev/v2"])

    def test_referenced_versions_stay(self):
        # a pending promotion still names the dev version it was requested from
        self.assertEqual(self.doomed(self.rels("dev", [0, 1, 2]), {"keep": 1}, refs=["c1/app/dev/v2"]), ["c1/app/dev/v1"])

    def test_removed_environment_keeps_only_days(self):
        rels = self.rels("branch-x", [0, 1, 200])
        self.assertEqual(len(self.doomed(rels, {"keep": 3})), 3)
        self.assertEqual(self.doomed(rels, {"keep": 3, "days": 90}), ["c1/app/branch-x/v2"])

    def test_unconfigured_apps_are_left_alone(self):
        self.assertEqual(self.doomed(self.rels("dev", [0, 1]), None), [])


class Policy(unittest.TestCase):
    def test_cluster_default_and_tenant_override(self):
        root = Path(tempfile.mkdtemp())
        (root / "clusters/c1").mkdir(parents=True)
        (root / "tenants").mkdir()
        (root / "clusters/c1/cicd-cluster.yaml").write_text(yaml.safe_dump({"evidence": {"repo": "cicd/evidence"}}))
        (root / "tenants/audited.yaml").write_text(yaml.safe_dump({"spec": {"evidence": {"keep": 3, "days": 90}}}))
        self.assertEqual(evidence.policy(root, "c1", "plain"), {"repo": "cicd/evidence", "keep": 1, "days": None})
        self.assertEqual(evidence.policy(root, "c1", "audited"), {"repo": "cicd/evidence", "keep": 3, "days": 90})
        self.assertIsNone(evidence.policy(root, "c2", "plain"))

    def test_one_app_alone(self):
        root = Path(tempfile.mkdtemp())
        (root / "clusters/c1").mkdir(parents=True)
        (root / "tenants").mkdir()
        (root / "clusters/c1/cicd-cluster.yaml").write_text("zone: x\n")
        (root / "tenants/trial.yaml").write_text(yaml.safe_dump({"spec": {"evidence": {"repo": "cicd/evidence"}}}))
        self.assertEqual(evidence.policy(root, "c1", "trial"), {"repo": "cicd/evidence", "keep": 1, "days": None})
        self.assertIsNone(evidence.policy(root, "c1", "other"))

    def test_no_token_keeps_evidence_inline(self):
        root = Path(tempfile.mkdtemp())
        (root / "clusters/c1").mkdir(parents=True)
        (root / "clusters/c1/cicd-cluster.yaml").write_text(yaml.safe_dump({"evidence": {"repo": "cicd/evidence"}}))
        with mock.patch.dict(os.environ, {"FORGEJO_TOKEN": "", "GITHUB_SERVER_URL": "https://forge.test"}):
            self.assertIsNone(evidence.active(root, "c1"))


class Render(unittest.TestCase):
    """A deploy with an evidence repo configured: the environment keeps evidence.json, the release the scans."""

    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        shutil.copytree(REPO / "clusters", self.root / "clusters")
        cfg = self.root / "clusters/c-local/cicd-cluster.yaml"
        c = yaml.safe_load(cfg.read_text())
        c["evidence"] = {"repo": "cicd/evidence", "keep": 1}
        cfg.write_text(yaml.safe_dump(c))
        self.sec = Path(tempfile.mkdtemp())
        for n in ("security.json", "sbom.cdx.json", "grype.json", "opengrep.sarif", "findings-source.json"):
            (self.sec / n).write_text('{"findings": [], "gate": {}}' if n == "security.json" else "{}")
        self.forge = FakeForge()
        env = {"FORGEJO_TOKEN": "t", "GITHUB_SERVER_URL": "https://forge.test"}
        self.patches = [mock.patch.dict(os.environ, env), mock.patch.object(evidence, "Forge", lambda: self.forge)]
        for p in self.patches:
            p.start()

    def tearDown(self):
        for p in self.patches:
            p.stop()

    def test_deploy_publishes_every_scan(self):
        app = cicd.load_app(str(REPO / "examples/hello/cicd.yaml"))
        cl = cicd.load_cluster(self.root, "c-local")
        out = cicd.render_env(self.root, app, cl, "dev", None, "localhost:5000/hello@" + DIGEST, "", {"commit": "abc"},
                              security_dir=self.sec)
        ev = out / "evidence"
        self.assertEqual(sorted(p.name for p in ev.iterdir()), ["evidence.json"])
        m = json.loads((ev / "evidence.json").read_text())
        self.assertEqual(sorted(m["files"]), ["findings-source.json", "grype.json", "opengrep.sarif", "sbom.cdx.json", "security.json"])
        self.assertTrue((out / "security-record.json").exists())    # the gate summary stays where the dashboard reads it
        self.assertEqual(m["meta"]["commit"], "abc")
        self.assertEqual(evidence.referenced(self.root), {m["tag"]})


class Backfill(unittest.TestCase):
    def test_applied_promotions_keep_checksums_only(self):
        root = Path(tempfile.mkdtemp())
        (root / "clusters/c1").mkdir(parents=True)
        (root / "clusters/c1/cicd-cluster.yaml").write_text(yaml.safe_dump({"evidence": {"repo": "cicd/evidence"}}))
        env_ev = root / "envs/c1/app/dev/evidence"
        env_ev.mkdir(parents=True)
        (env_ev.parent / "cicd-env.yaml").write_text("app: app\n")
        (env_ev / "sbom.cdx.json").write_text("{}")
        done_ev = root / "promotions/done/app-prod-1/evidence"
        done_ev.mkdir(parents=True)
        (done_ev.parent / "promotion.yaml").write_text(yaml.safe_dump({"id": "app-prod-1", "app": "app", "cluster": "c1"}))
        (done_ev / "sbom.cdx.json").write_text("{}")
        (done_ev / "approval.json").write_text("{}")
        forge = FakeForge()
        out = evidence.backfill(root, "c1", forge, "abc1234")
        self.assertEqual(len(out), 2)
        self.assertEqual(len(forge.rels), 1)
        m = json.loads((done_ev / "evidence.json").read_text())
        self.assertIsNone(m["tag"])
        self.assertIn("abc1234", m["kept"])
        self.assertEqual(sorted(p.name for p in done_ev.iterdir()), ["approval.json", "evidence.json"])


if __name__ == "__main__":
    unittest.main()
