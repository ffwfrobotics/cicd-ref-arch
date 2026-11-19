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

    def test_branch_env_layout(self):
        out = self.render("branch", "feat/x")
        k = yaml.safe_load((out / "kustomization.yaml").read_text())
        self.assertEqual(k["namespace"], "hello-feat-x")
        self.assertEqual(k["images"][0]["digest"], DIGEST)
        objs = list(yaml.safe_load_all((out / "platform.yaml").read_text()))
        kinds = [o["kind"] for o in objs]
        self.assertEqual(kinds, ["NetworkPolicy", "InterceptorRoute", "ScaledObject"])
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
        try:
            self.assertEqual(cicd.apply_due(self.root, B), 0)          # not due
            p = next((self.root / "promotions/pending").glob("*/promotion.yaml"))
            d = yaml.safe_load(p.read_text())
            d["notBefore"] = "2000-01-01T00:00:00Z"
            p.write_text(yaml.safe_dump(d))
            self.assertEqual(cicd.apply_due(self.root, B), 1)
        finally:
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
            self.assertEqual(cicd.apply_due(self.root, B), 0)
        finally:
            del os.environ["FORGEJO_API"], os.environ["FORGEJO_TOKEN"]
        self.assertFalse((self.root / "envs/c-local/hello/prod").exists())


if __name__ == "__main__":
    unittest.main()
