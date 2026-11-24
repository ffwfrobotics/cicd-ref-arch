"""Build-only apps (docs/enrollment.md): images built, scanned and kept as evidence by digest, and no
environment at all. Run: python3 -m unittest discover -s tests"""
import argparse
import datetime as dt
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "tools"))
sys.path.insert(0, str(REPO / "tests"))
import cicd  # noqa: E402
import evidence  # noqa: E402
from test_evidence import FakeForge  # noqa: E402

DIGEST = "sha256:" + "b" * 64
BUILDS = [{"name": "controller", "context": ".", "dockerfile": "Dockerfile"},
          {"name": "harness", "context": "harness"}]


def tenant(name="factory", **spec):
    return {"apiVersion": cicd.API, "kind": "Tenant", "metadata": {"name": name},
            "spec": {"tenant": "t", "repo": "o/factory", "clusters": ["c1"], **spec}}


def root_with(*tenants) -> Path:
    root = Path(tempfile.mkdtemp())
    (root / "tenants").mkdir()
    for t in tenants:
        (root / "tenants" / f"{t['metadata']['name']}.yaml").write_text(yaml.safe_dump(t))
    (root / "tenants/_writable.yaml").write_text("owners: []\nrepos: [o/factory]\n")
    return root


def run_cicd(root: Path, *a):
    return subprocess.run([sys.executable, str(REPO / "tools/cicd.py"), "--root", str(root), *a],
                          capture_output=True, text=True)


class Spec(unittest.TestCase):
    def test_targets_and_defaults(self):
        s = cicd.tenant_spec(tenant(mode="build-only", builds=BUILDS))
        self.assertEqual(s["builds"], [
            {"name": "controller", "context": ".", "dockerfile": "Dockerfile", "image": "factory-controller"},
            {"name": "harness", "context": "harness", "dockerfile": "harness/Dockerfile", "image": "factory-harness"}])
        self.assertTrue(cicd.build_only(s))

    def test_rejects(self):
        bad = [dict(mode="build-only"),                                           # no builds
               dict(mode="build-only", builds=[]),
               dict(mode="build-only", builds=[{"name": "Bad_Name"}]),
               dict(mode="build-only", builds=[{"name": "a"}, {"name": "a"}]),
               dict(mode="build-only", builds=[{"name": "a", "context": "../x"}]),
               dict(mode="build-only", builds=[{"name": "a", "dockerfile": "/etc/Dockerfile"}]),
               dict(mode="build-only", builds=BUILDS, sources=[{"path": "s", "repo": "o/s"}]),
               dict(mode="build-only", builds=BUILDS, image={"repository": "x", "tag": "y"}),
               dict(mode="build-only", builds=BUILDS, kind="Stack"),
               dict(builds=BUILDS)]                                               # builds on a direct app
        for spec in bad:
            with self.assertRaises(ValueError, msg=spec):
                cicd.tenant_spec(tenant(**spec))

    def test_the_enrolled_factory_record(self):
        s = cicd.tenant_spec(cicd.load_tenants(REPO)["factory"])
        self.assertEqual([(b["image"], b["context"], b["dockerfile"]) for b in s["builds"]],
                         [("factory-controller", ".", "Dockerfile"), ("factory-harness", "harness", "harness/Dockerfile")])

    def test_github_output_names_the_builds(self):
        root = root_with(tenant(mode="build-only", builds=BUILDS))
        r = run_cicd(root, "tenant", "factory", "--github-output")
        self.assertEqual(r.returncode, 0, r.stderr)
        out = dict(l.split("=", 1) for l in r.stdout.splitlines())
        self.assertEqual(out["mode"], "build-only")
        self.assertEqual([b["image"] for b in json.loads(out["builds"])], ["factory-controller", "factory-harness"])
        # other apps say builds=[] (the pipeline's matrix is never asked to run on them)
        root = root_with(tenant(name="hello"))
        self.assertIn("builds=[]", run_cicd(root, "tenant", "hello", "--github-output").stdout)


class NoEnvironments(unittest.TestCase):
    """Every path that writes an environment, a promotion or a pause refuses a build-only app."""

    def setUp(self):
        self.root = root_with(tenant(mode="build-only", builds=BUILDS))
        shutil.copytree(REPO / "clusters", self.root / "clusters")
        self.app = self.root / "cicd.yaml"      # even if the repo carried an app contract
        self.app.write_text(yaml.safe_dump({"apiVersion": cicd.API, "kind": "App", "metadata": {"name": "factory"},
                                            "spec": {"environments": {"dev": {"branch": "main"}}}}))
        (self.root / "app.yaml").write_text("")

    def test_render_refuses(self):
        r = run_cicd(self.root, "render", str(self.app), "--env", "dev", "--branch", "main", "--cluster", "c-local",
                     "--image", f"localhost:5000/factory@{DIGEST}", "--manifests", str(self.root / "app.yaml"), "--repo", "o/factory")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("build-only", r.stderr)
        self.assertFalse((self.root / "envs").exists())

    def test_which_env_skips(self):
        r = run_cicd(self.root, "which-env", str(self.app), "--branch", "main", "--cluster", "c-local")
        self.assertEqual(r.stdout.strip(), "skip")

    def test_promotion_and_self_service_refuse(self):
        r = run_cicd(self.root, "request-promotion", "--app", "factory", "--cluster", "c-local", "--requested-by", "x")
        self.assertIn("build-only", r.stderr)
        for action in ("pause", "resume", "remove-env"):
            r = run_cicd(self.root, "manage", action, "--app", "factory", "--branch", "main", "--cluster", "c-local", "--by", "x")
            self.assertNotEqual(r.returncode, 0, action)
            self.assertIn("build-only", r.stderr)
        self.assertFalse((self.root / "promotions").exists())
        self.assertFalse((self.root / "envs").exists())

    def test_bump_has_nothing_to_move(self):
        a = argparse.Namespace(app="factory", source="o/src", branch="main", sha="a" * 40, actor="", server="file:///nowhere")
        with self.assertRaises(SystemExit):
            cicd.bump(self.root, a)


class Record(unittest.TestCase):
    def setUp(self):
        self.root = root_with(tenant(mode="build-only", builds=BUILDS), tenant(name="hello"))
        self.out = Path(tempfile.mkdtemp())
        (self.out / "security.json").write_text(json.dumps({"gate": {
            "env": "prod", "mode": "enforce", "status": "fail", "blocking": 2, "counts": {"vuln": 2}, "notes": []}}))

    def record(self, *extra, app="factory", target="harness", image=f"localhost:5000/factory-harness@{DIGEST}"):
        return run_cicd(self.root, "build-record", "--app", app, "--target", target, "--cluster", "c1", "--image", image,
                        "--commit", "c" * 40, "--branch", "main", "--run-url", "https://forge/run/1",
                        "--security", str(self.out / "security.json"), "--out", str(self.out / "build.json"), *extra)

    def test_writes_the_digest_and_the_gate(self):
        r = self.record()
        self.assertEqual(r.returncode, 0, r.stderr)
        rec = json.loads((self.out / "build.json").read_text())
        self.assertEqual((rec["schema"], rec["app"], rec["target"], rec["digest"], rec["repository"], rec["dockerfile"]),
                         (cicd.BUILD_SCHEMA, "factory", "harness", DIGEST, "localhost:5000/factory-harness", "harness/Dockerfile"))
        self.assertEqual(rec["gate"], {"env": "prod", "mode": "enforce", "status": "fail", "blocking": 2, "counts": {"vuln": 2}})

    def test_refuses_what_is_not_a_build(self):
        self.assertNotEqual(self.record(target="nope").returncode, 0)
        self.assertNotEqual(self.record(app="hello").returncode, 0)
        self.assertNotEqual(self.record(image="localhost:5000/factory-harness:abc1234").returncode, 0)   # a tag, not a digest


class Evidence(unittest.TestCase):
    NOW = dt.datetime(2026, 11, 22, 12, tzinfo=dt.timezone.utc)

    def test_retention_keeps_the_newest_of_each_target(self):
        rels = [{"tag_name": f"c1/factory/build-{t}/v{i}", "created_at": (self.NOW - dt.timedelta(days=i)).isoformat()}
                for t in ("controller", "harness") for i in range(3)]
        live = {("c1", "factory", "build-*")}
        doomed = sorted(evidence.doomed(rels, set(), live, lambda c, a: {"keep": 1}, self.NOW))
        self.assertEqual(doomed, [f"c1/factory/build-{t}/v{i}" for t in ("controller", "harness") for i in (1, 2)])
        # unenrolled: no longer live, so only `days` would keep them
        self.assertEqual(len(evidence.doomed(rels, set(), set(), lambda c, a: {"keep": 1}, self.NOW)), 6)

    def test_build_only_apps_are_found(self):
        root = root_with(tenant(mode="build-only", builds=BUILDS), tenant(name="hello"),
                         tenant(name="other", mode="build-only", builds=BUILDS, clusters=["c2"]))
        self.assertEqual(evidence.build_only_apps(root, "c1"), ["factory"])

    def publish(self, forge, target, digest, branch="main"):
        d = Path(tempfile.mkdtemp()) / "evidence"
        d.mkdir()
        (d / "sbom.cdx.json").write_text('{"components": []}')
        (d / "build.json").write_text(json.dumps({"schema": cicd.BUILD_SCHEMA, "app": "factory", "target": target,
                                                  "image": f"localhost:5000/factory-{target}@{digest}", "digest": digest,
                                                  "branch": branch, "gate": {"status": "pass"}}))
        return evidence.publish(d, "c1", "factory", f"build-{target}", {"repo": "cicd/evidence", "keep": 1}, forge)

    def test_latest_builds(self):
        forge = FakeForge()
        old, new = "sha256:" + "1" * 64, "sha256:" + "2" * 64
        self.publish(forge, "controller", old)
        self.publish(forge, "harness", old)
        self.publish(forge, "controller", new)
        self.publish(forge, "harness", "sha256:" + "3" * 64, branch="feat")
        got = evidence.latest_builds(forge, "cicd/evidence", "c1", "factory")
        self.assertEqual({t: b["digest"] for t, b in got.items()}, {"controller": new, "harness": "sha256:" + "3" * 64})
        got = evidence.latest_builds(forge, "cicd/evidence", "c1", "factory", branch="main")
        self.assertEqual({t: b["digest"] for t, b in got.items()}, {"controller": new, "harness": old})
        self.assertTrue(got["controller"]["tag"].startswith("c1/factory/build-controller/"))

    def test_latest_builds_refuses_a_record_for_another_target(self):
        forge = FakeForge()
        m = self.publish(forge, "controller", DIGEST)
        url = m["files"]["build.json"]["url"]
        forge.blobs[url] = forge.blobs[url].replace(b'"controller"', b'"harness"   ')     # same size, other target
        with self.assertRaises(RuntimeError):
            evidence.latest_builds(forge, "cicd/evidence", "c1", "factory")


class Pipeline(unittest.TestCase):
    """The workflow's routing: a build-only app goes to the images job only."""

    def setUp(self):
        self.wf = yaml.safe_load((REPO / ".forgejo/workflows/pipeline.yaml").read_text())
        self.jobs = self.wf["jobs"]

    def test_images_job_builds_each_target_and_deploys_nothing(self):
        j = self.jobs["images"]
        self.assertEqual(j["if"], "needs.route.outputs.env == 'build-only'")
        self.assertIn("fromJSON(needs.route.outputs.builds)", j["strategy"]["matrix"]["build"])
        uses = [s.get("uses", "") for s in j["steps"]]
        self.assertNotIn("./.cicd/actions/deploy-env", uses)
        self.assertIn("./.cicd/actions/security", uses)
        sec = next(s for s in j["steps"] if s.get("uses") == "./.cicd/actions/security")
        self.assertEqual(sec["with"]["env"], "prod")       # images for production: gated under the prod policy

    def test_no_other_job_runs_for_build_only(self):
        for name, j in self.jobs.items():
            if name in ("route", "images"):
                continue
            cond = j.get("if", "")
            # each other job runs only for a named env (dev/branch/manage/bump/stack) or excludes build-only
            self.assertTrue("build-only" in cond or "== 'dev'" in cond or "needs.deliver" in cond
                            or "== 'bump'" in cond or "== 'stack'" in cond or "== 'manage'" in cond, name)


if __name__ == "__main__":
    unittest.main()
