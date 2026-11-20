"""Unit tests for tools/cicd.py: names, hosts, render, promotion, gc. Run: python3 -m unittest -v"""
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "tools"))
import cicd  # noqa: E402
import yaml  # noqa: E402

DIGEST = "sha256:" + "a" * 64


class Names(unittest.TestCase):
    def test_slug_dns_safe(self):
        self.assertEqual(cicd.branch_slug("hello", "feat/Login-Page_v2"), "feat-login-page-v2")

    def test_reserved(self):
        self.assertEqual(cicd.branch_slug("hello", "dev"), "dev-br")
        self.assertEqual(cicd.branch_slug("hello", "PROD"), "prod-br")

    def test_long_branch_fits_one_label_and_is_stable(self):
        b = "feature/" + "x" * 100
        s = cicd.branch_slug("hello", b)
        self.assertLessEqual(len("hello-" + s), 63)
        self.assertEqual(s, cicd.branch_slug("hello", b))
        self.assertNotEqual(s, cicd.branch_slug("hello", b + "y"))


class Render(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        shutil.copytree(REPO / "clusters", self.root / "clusters")
        self.app_path = REPO / "examples/hello/cicd.yaml"
        self.app = cicd.load_app(str(self.app_path))
        self.cl = cicd.load_cluster(self.root, "c-local")
        subprocess.run(["git", "init", "-q", str(self.root)], check=True)

    def tearDown(self):
        shutil.rmtree(self.root)

    def render(self, env, branch=None):
        return cicd.render_env(self.root, self.app, self.cl, env, branch, "localhost:5000/hello@" + DIGEST,
                               "apiVersion: v1\nkind: Service\nmetadata: {name: hello}\n", {},
                               app_config_text=self.app_path.read_text())

    def test_hosts(self):
        self.assertEqual(cicd.hosts_for(self.app, "dev", None, "c-local", "k.ffwf.net"),
                         ["hello-dev.c-local.k.ffwf.net"])
        self.assertEqual(cicd.hosts_for(self.app, "branch", "feat/x", "c-local", "k.ffwf.net"),
                         ["hello-feat-x.c-local.k.ffwf.net"])

    def test_dev_replaces_the_pending_stand_in(self):
        standin = self.render("branch", "master")
        self.assertTrue(standin.exists())
        self.render("dev", "master")
        self.assertFalse(standin.exists())

    def test_branch_env_layout(self):
        out = self.render("branch", "feat/x")
        k = yaml.safe_load((out / "kustomization.yaml").read_text())
        self.assertEqual(k["namespace"], "hello-feat-x")
        self.assertEqual(k["images"][0]["digest"], DIGEST)
        objs = list(yaml.safe_load_all((out / "platform.yaml").read_text()))
        kinds = [o["kind"] for o in objs]
        self.assertEqual(kinds, ["NetworkPolicy", "InterceptorRoute", "ScaledObject", "RoleBinding"])   # RoleBinding: the runtime check reads the env
        so = objs[2]["spec"]
        self.assertEqual((so["minReplicaCount"], so["cooldownPeriod"]), (0, 900))
        self.assertEqual(objs[1]["spec"]["rules"][0]["hosts"], ["hello-feat-x.c-local.k.ffwf.net"])

    def test_tag_is_refused(self):
        with self.assertRaises(SystemExit):
            cicd.render_env(self.root, self.app, self.cl, "dev", None, "localhost:5000/hello:latest", "", {})

    def test_index_lists_envs(self):
        self.render("dev")
        self.render("branch", "a")
        idx = yaml.safe_load(cicd.build_index(self.root, "c-local").read_text())
        self.assertEqual(idx["resources"], ["hello/branch-a", "hello/dev"])

    def test_promotion_waits_for_time_then_applies(self):
        self.render("dev")
        git = ["git", "-C", str(self.root), "-c", "user.name=t", "-c", "user.email=t@t"]
        subprocess.run(git + ["add", "-A"], check=True)
        subprocess.run(git + ["commit", "-qm", "dev"], check=True)

        class A:  # argparse stand-in
            app, cluster, source, to, requested_by, reason = "hello", "c-local", "dev", "prod", "alice", ""
            not_before = "2999-01-01T00:00:00Z"
        cicd.request_promotion(self.root, A)

        class B:
            cluster = "c-local"
        os.environ["CICD_SKIP_APPROVAL_CHECK"] = "1"
        real_security_of = cicd.security_of
        try:
            self.assertEqual(cicd.apply_due(self.root, B), (0, 0))     # not due
            p = next((self.root / "promotions/pending").glob("*/promotion.yaml"))
            d = yaml.safe_load(p.read_text())
            d["notBefore"] = "2000-01-01T00:00:00Z"
            p.write_text(yaml.safe_dump(d))
            cicd.security_of = lambda *a: (False, "security gate fail (1 blocking: vuln/CVE-X)")
            self.assertEqual(cicd.apply_due(self.root, B), (0, 1))     # due, approved, fails the gate
            self.assertTrue(p.exists())                                # stays pending
            cicd.security_of = lambda *a: (True, "security gate pass")
            self.assertEqual(cicd.apply_due(self.root, B), (1, 0))
        finally:
            cicd.security_of = real_security_of
            del os.environ["CICD_SKIP_APPROVAL_CHECK"]
        meta = yaml.safe_load((self.root / "envs/c-local/hello/prod/cicd-env.yaml").read_text())
        self.assertEqual(meta["image"], "localhost:5000/hello@" + DIGEST)
        self.assertEqual(meta["hosts"], ["hello.c-local.k.ffwf.net"])

    def test_unapproved_promotion_is_not_applied(self):
        self.render("dev")
        git = ["git", "-C", str(self.root), "-c", "user.name=t", "-c", "user.email=t@t"]

        class A:
            app, cluster, source, to, requested_by, reason, not_before = "hello", "c-local", "dev", "prod", "a", "", None
        cicd.request_promotion(self.root, A)
        subprocess.run(git + ["add", "-A"], check=True)
        subprocess.run(git + ["commit", "-qm", "direct push, no PR"], check=True)

        class B:
            cluster = "c-local"
        os.environ.update(FORGEJO_API="http://127.0.0.1:9/api/v1/repos/x/y", FORGEJO_TOKEN="t")
        try:
            self.assertEqual(cicd.apply_due(self.root, B), (0, 1))
        finally:
            del os.environ["FORGEJO_API"], os.environ["FORGEJO_TOKEN"]
        self.assertFalse((self.root / "envs/c-local/hello/prod").exists())


class Routing(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        (self.root / "tenants").mkdir()
        for name in ("hello", "other"):
            (self.root / f"tenants/{name}.yaml").write_text(yaml.safe_dump({
                "apiVersion": cicd.API, "kind": "Tenant", "metadata": {"name": name},
                "spec": {"tenant": "t1", "repo": f"o/{name}", "clusters": ["c-local"]}}))
        (self.root / "tenants/_limits.yaml").write_text("t1: {branchLimit: 2}\n")
        self.app = cicd.load_app(str(REPO / "examples/hello/cicd.yaml"))

    def env(self, app, d):
        p = self.root / f"envs/c-local/{app}/{d}"
        p.mkdir(parents=True)
        (p / "kustomization.yaml").write_text("{}")

    def test_limit_counts_the_whole_tenant(self):
        self.assertEqual(cicd.route(self.root, self.app, "feat/a", "c-local"), "branch")
        self.env("hello", "branch-feat-a")
        self.env("other", "branch-x")
        self.assertEqual(cicd.route(self.root, self.app, "feat/b", "c-local"), "skip-limit")
        self.assertEqual(cicd.route(self.root, self.app, "feat/a", "c-local"), "branch")   # already has one
        self.assertEqual(cicd.route(self.root, self.app, "master", "c-local"), "dev")       # dev always

    def test_pending_gets_branch_envs_only(self):
        t = self.root / "tenants/hello.yaml"
        d = yaml.safe_load(t.read_text())
        d["spec"]["status"] = "pending"
        t.write_text(yaml.safe_dump(d))
        self.assertEqual(cicd.route(self.root, self.app, "master", "c-local"), "branch")   # no dev host yet
        d["spec"]["status"] = "approved"
        t.write_text(yaml.safe_dump(d))
        self.assertEqual(cicd.route(self.root, self.app, "master", "c-local"), "dev")

    def test_pause_resume_remove(self):
        self.env("hello", "branch-feat-a")
        class A:
            action, app, app_config, branch, cluster, by = "pause", "hello", str(REPO / "examples/hello/cicd.yaml"), "feat/a", "c-local", "ada"
        cicd.manage(self.root, A)
        self.assertFalse((self.root / "envs/c-local/hello/branch-feat-a").exists())
        self.assertEqual(cicd.route(self.root, self.app, "feat/a", "c-local"), "skip-paused")
        A.action = "resume"
        cicd.manage(self.root, A)
        self.assertEqual(cicd.route(self.root, self.app, "feat/a", "c-local"), "branch")
        self.assertFalse(cicd.paused_file(self.root, "c-local", "hello").exists())
        self.env("hello", "branch-feat-a")
        A.action = "remove-env"
        cicd.manage(self.root, A)
        self.assertFalse((self.root / "envs/c-local/hello/branch-feat-a").exists())


class Tenants(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        (self.root / "tenants").mkdir()
        (self.root / "tenants/hello.yaml").write_text(yaml.safe_dump({
            "apiVersion": cicd.API, "kind": "Tenant", "metadata": {"name": "hello"},
            "spec": {"repo": "ffwf/cicd-ref-arch", "clusters": ["c-local"]}}))
        self.app = cicd.load_app(str(REPO / "examples/hello/cicd.yaml"))

    def test_enrolled_repo_and_cluster(self):
        cicd.check_tenant(self.root, self.app, "ffwf/cicd-ref-arch", "c-local")
        with self.assertRaises(SystemExit):
            cicd.check_tenant(self.root, self.app, "someone/else", "c-local")
        with self.assertRaises(SystemExit):
            cicd.check_tenant(self.root, self.app, "ffwf/cicd-ref-arch", "c-other")

    def test_not_enrolled(self):
        app = dict(self.app, metadata={"name": "stranger"})
        with self.assertRaises(SystemExit):
            cicd.check_tenant(self.root, app, "ffwf/x", "c-local")


if __name__ == "__main__":
    unittest.main()


class DispatchMissing(unittest.TestCase):
    """The safety net under the webhook: only unseen, recent heads of moved apps on this cluster."""

    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        (self.root / "tenants").mkdir()
        for name, repo, cl in [("demo", "o/demo", ["c1"]), ("old", "o/old", ["c1"]), ("hello", "o/platform", ["c1"]),
                               ("far", "o/far", ["c2"])]:
            (self.root / "tenants" / f"{name}.yaml").write_text(yaml.safe_dump(
                {"metadata": {"name": name}, "spec": {"repo": repo, "clusters": cl}}))
        self.addCleanup(shutil.rmtree, self.root)

    def test_dispatches_only_what_is_missing(self):
        import datetime as dt
        import json
        import urllib.error
        now = cicd.now_utc()
        recent = (now - dt.timedelta(minutes=10)).isoformat()
        old = (now - dt.timedelta(days=3)).isoformat()
        sent = []

        def api(server, method, path, body=None):
            if method == "POST":
                sent.append(body["inputs"])
                return None
            if "/actions/runs" in path:
                return {"workflow_runs": [{"created": recent, "event_payload": json.dumps({"inputs": {"sha": "a" * 40}})}]}
            if path.endswith("/contents/.forgejo/workflows/cicd.yaml"):
                if path.startswith("/repos/o/old/"):
                    return {"name": "cicd.yaml"}
                raise urllib.error.HTTPError(path, 404, "nf", {}, None)
            if path.startswith("/repos/o/demo/branches"):
                return [{"name": "main", "commit": {"id": "a" * 40, "timestamp": recent}},           # already run
                        {"name": "feat", "commit": {"id": "b" * 40, "timestamp": recent, "author": {"username": "ada"}}},
                        {"name": "stale", "commit": {"id": "c" * 40, "timestamp": old}}]
            raise AssertionError(path)

        orig = cicd.forge_api
        cicd.forge_api = api
        try:
            args = type("A", (), {"cluster": "c1", "repo": "o/platform", "server": "https://f", "within_h": 6})()
            n = cicd.dispatch_missing(self.root, args)
        finally:
            cicd.forge_api = orig
        self.assertEqual(n, 1)
        self.assertEqual(sent, [{"app": "demo", "branch": "feat", "sha": "b" * 40, "action": "deploy", "actor": "ada"}])
