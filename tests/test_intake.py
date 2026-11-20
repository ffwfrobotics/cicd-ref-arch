"""Unit tests for tools/intake.py: the contract checks and their defaults. Run: python3 -m unittest -v"""
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "tools"))
import intake  # noqa: E402


def states(results):
    return {r["check"]: r["state"] for r in results}


class Intake(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.d)

    def test_example_meets_the_contract(self):
        app = self.d / "hello"
        shutil.copytree(REPO / "examples/hello", app)
        results, filled = intake.check(app, "hello", "master", fill=True)
        self.assertEqual({s for s in states(results).values()}, {"ok"}, results)
        self.assertEqual(filled, [])

    def test_only_a_dockerfile(self):
        (self.d / "Dockerfile").write_text("ARG B=python:3.12@sha256:" + "a" * 64 + "\nFROM ${B}\nEXPOSE 5000\n")
        results, filled = intake.check(self.d, "bare", "main", fill=True)
        s = states(results)
        self.assertEqual((s["cicd-yaml"], s["deploy-base"], s["tests"], s["base-pinned"]), ("assumed", "assumed", "warn", "ok"))
        self.assertTrue(intake.runnable(results))
        self.assertIn("containerPort: 5000", (self.d / "deploy/deployment.yaml").read_text())
        # what was generated meets the rest of the contract
        self.assertEqual({k for k, v in s.items() if v not in ("ok",)}, {"cicd-yaml", "deploy-base", "tests"})
        # the jobs after route fill in the same files again
        again, _ = intake.check(self.d, "bare", "main", fill=True)
        self.assertEqual(states(again)["cicd-yaml"], "ok")

    def test_nothing_to_run(self):
        results, _ = intake.check(self.d, "empty", "main", fill=True)
        self.assertEqual(states(results)["dockerfile"], "missing")
        self.assertFalse(intake.runnable(results))
        self.assertIn("Dockerfile", intake.summary(results))

    def test_wrong_name_stops(self):
        (self.d / "cicd.yaml").write_text("metadata: {name: other}\nspec: {}\n")
        results, _ = intake.check(self.d, "mine", "main", fill=True)
        self.assertFalse(intake.runnable(results))

    def test_problems_name_file_and_line(self):
        app = self.d / "hello"
        shutil.copytree(REPO / "examples/hello", app)
        dep = app / "deploy/deployment.yaml"
        dep.write_text(dep.read_text().replace("spec:\n", "spec:\n  replicas: 2\n", 1).replace("readinessProbe", "xReadinessProbe"))
        results, _ = intake.check(app, "hello", "master", fill=False)
        r = {x["check"]: x for x in results}
        self.assertEqual(r["no-replicas"]["state"], "warn")
        self.assertEqual((r["no-replicas"]["file"], r["no-replicas"]["line"]), ("deploy/deployment.yaml", 5))
        self.assertEqual(r["readiness"]["state"], "warn")

    def test_doc_is_current(self):
        self.assertEqual((REPO / "docs/contract.md").read_text(), intake.doc(),
                         "docs/contract.md is generated: python3 tools/intake.py doc > docs/contract.md")


if __name__ == "__main__":
    unittest.main()
