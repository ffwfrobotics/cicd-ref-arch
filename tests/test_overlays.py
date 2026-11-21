"""deploy-<env>/ overlays: intake's `overlays` check (docs/enrollment.md). Needs kustomize or kubectl."""
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "tools"))
import intake  # noqa: E402

KUBECTL = Path(os.environ.get("KUBECTL_DIR", "/home/john/Development/kubecon2026shenanigans"))
if not shutil.which("kustomize") and not shutil.which("kubectl") and (KUBECTL / "kubectl").exists():
    os.environ["PATH"] = f"{KUBECTL}:{os.environ['PATH']}"
HAVE = bool(shutil.which("kustomize") or shutil.which("kubectl"))


def overlay(patch: str) -> str:
    return yaml.safe_dump({"apiVersion": "kustomize.config.k8s.io/v1beta1", "kind": "Kustomization",
                           "resources": ["../deploy"], "patches": [{"target": {"kind": "Deployment", "name": "o"}, "patch": patch}]})


@unittest.skipUnless(HAVE, "needs kustomize or kubectl")
class Overlays(unittest.TestCase):
    def setUp(self):
        self.app = Path(tempfile.mkdtemp())
        (self.app / "deploy").mkdir()
        for name, text in intake.default_deploy("o", 8080).items():
            (self.app / "deploy" / name).write_text(text)
        self.results = []

    def put(self, cid, state, detail="", file=None, line=None):
        self.results.append((cid, state, detail))

    def run_check(self, spec=None):
        self.results = []
        intake.overlay_check(self.app, self.app / "deploy", spec or {}, self.put)
        return self.results[-1]

    def add(self, env, patch):
        d = self.app / f"deploy-{env}"
        d.mkdir(exist_ok=True)
        (d / "kustomization.yaml").write_text(overlay(patch))

    def test_none_is_ok(self):
        self.assertEqual(self.run_check()[:2], ("overlays", "ok"))

    def test_bigger_prod_is_ok_and_allowed(self):
        self.add("prod", "- op: replace\n  path: /spec/template/spec/containers/0/resources/requests/memory\n  value: 512Mi\n")
        self.assertEqual(self.run_check({"overlays": {"allow": ["resources"]}})[:2], ("overlays", "ok"))

    def test_outside_the_allowlist_warns(self):
        self.add("prod", "- op: add\n  path: /spec/template/spec/hostNetwork\n  value: true\n")
        cid, state, detail = self.run_check({"overlays": {"allow": ["resources", "replicas"]}})
        self.assertEqual(state, "warn")
        self.assertIn("hostNetwork", detail)

    def test_dropping_requests_warns_and_broken_stops(self):
        self.add("dev", "- op: remove\n  path: /spec/template/spec/containers/0/resources\n")
        self.assertEqual(self.run_check()[1], "warn")
        (self.app / "deploy-prod").mkdir()
        (self.app / "deploy-prod/kustomization.yaml").write_text("resources: [missing.yaml]\n")
        self.assertEqual(self.run_check()[1], "missing")


if __name__ == "__main__":
    unittest.main()
