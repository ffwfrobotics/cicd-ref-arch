"""Enrollment modes: tenant records and bumping a source submodule (docs/enrollment.md).
Run: python3 -m unittest discover -s tests"""
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "tools"))
import cicd  # noqa: E402


def tenant(**spec):
    return {"metadata": {"name": "x"}, "spec": {"tenant": "t", "repo": "o/x", **spec}}


class Spec(unittest.TestCase):
    def test_old_records_are_direct(self):
        s = cicd.tenant_spec(tenant())
        self.assertEqual((s["kind"], s["mode"], s["path"], s["sources"]), ("App", "direct", ".", []))

    def test_wrapped_defaults(self):
        s = cicd.tenant_spec(tenant(mode="wrapped", sources=[{"path": "src", "repo": "o/src"}]))
        self.assertEqual(s["sources"][0], {"path": "src", "repo": "o/src", "branch": "main", "update": "follow"})

    def test_rejects(self):
        bad = [dict(mode="weird"), dict(kind="Thing"), dict(sources=[{"path": "src", "repo": "o/s"}]),
               dict(mode="wrapped", sources=[{"path": "../x", "repo": "o/s"}]),
               dict(mode="wrapped", sources=[{"path": "src", "repo": "o/s", "update": "sometimes"}]),
               dict(mode="wrapped", sources=[{"path": "src", "repo": "o/a"}, {"path": "src", "repo": "o/b"}]),
               dict(mode="wrapped", sources=[{"path": "src"}])]
        for spec in bad:
            with self.assertRaises(ValueError, msg=spec):
                cicd.tenant_spec(tenant(**spec))


def git(cwd, *a):
    return subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@t", "-C", str(cwd), *a],
                          capture_output=True, text=True, check=True).stdout.strip()


class Bump(unittest.TestCase):
    """bump against local repos: the forge's URL is a file:// directory, its API is a stub."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.server = f"file://{self.tmp}/forge"
        (self.tmp / "forge/ffwf-iac").mkdir(parents=True)
        # the IaC root (bare, as on the forge), with a src submodule at commit A of the source
        self.src = self.tmp / "src"
        self.src.mkdir()
        git(self.src, "init", "-q", "-b", "main")
        (self.src / "a").write_text("a")
        git(self.src, "add", "a")
        git(self.src, "commit", "-qm", "A")
        self.a = git(self.src, "rev-parse", "HEAD")
        (self.src / "b").write_text("b")
        git(self.src, "add", "b")
        git(self.src, "commit", "-qm", "B")
        self.b = git(self.src, "rev-parse", "HEAD")
        work = self.tmp / "iac-work"
        work.mkdir()
        git(work, "init", "-q", "-b", "main")
        (work / "cicd.yaml").write_text("kind: App\n")
        git(work, "add", "cicd.yaml")
        git(work, "update-index", "--add", "--cacheinfo", f"160000,{self.a},src")
        git(work, "commit", "-qm", "wrap")
        self.bare = self.tmp / "forge/ffwf-iac/x.git"
        subprocess.run(["git", "clone", "-q", "--bare", str(work), str(self.bare)], check=True)
        # the platform repo's tenant record
        self.root = self.tmp / "root"
        (self.root / "tenants").mkdir(parents=True)
        self.update = "follow"
        self.prs = []
        self.real_api = cicd.api
        cicd.api = self.api
        os.environ["FORGEJO_TOKEN"] = "t"
        os.environ["RUNNER_TEMP"] = str(self.tmp)

    def tearDown(self):
        cicd.api = self.real_api
        del os.environ["FORGEJO_TOKEN"], os.environ["RUNNER_TEMP"]

    def api(self, method, server, path, token, body=None):
        if path == "/repos/ffwf-iac/x":
            return 200, {"default_branch": "main"}
        if path.startswith("/repos/o/src/git/commits/"):
            sha = path.rsplit("/", 1)[1]
            return (200, {}) if sha in (self.a, self.b) else (404, "no")
        if method == "POST" and path == "/repos/ffwf-iac/x/pulls":
            self.prs.append(body)
            return 201, {"number": len(self.prs)}
        return 404, "unexpected"

    def record(self):
        (self.root / "tenants/x.yaml").write_text(yaml.safe_dump({"metadata": {"name": "x"}, "spec": {
            "tenant": "t", "mode": "wrapped", "repo": "ffwf-iac/x",
            "sources": [{"path": "src", "repo": "o/src", "branch": "main", "update": self.update}]}}))

    def run_bump(self, branch, sha):
        class A:
            app, source, actor, server = "x", "o/src", "ada", self.server
        A.branch, A.sha = branch, sha
        return cicd.bump(self.root, A)

    def gitlink(self, ref):
        return git(self.bare, "rev-parse", f"{ref}:src")

    def test_follow_moves_dev_with_trailers(self):
        self.record()
        self.run_bump("main", self.b)
        self.assertEqual(self.gitlink("main"), self.b)
        msg = git(self.bare, "log", "-1", "--format=%B", "main")
        self.assertIn(f"Source-Commit: {self.b}", msg)
        self.assertIn("Requested-by: ada", msg)
        self.assertIn("already at", self.run_bump("main", self.b))            # a redelivered push changes nothing

    def test_other_branch_gets_its_own_iac_branch_and_goes_on_delete(self):
        self.record()
        self.run_bump("feat/x", self.b)
        self.assertEqual(self.gitlink("src/feat-x"), self.b)
        self.assertEqual(self.gitlink("main"), self.a)                         # dev untouched
        self.run_bump("feat/x", cicd.ZERO)
        r = subprocess.run(["git", "-C", str(self.bare), "rev-parse", "--verify", "-q", "src/feat-x"], capture_output=True)
        self.assertNotEqual(r.returncode, 0)

    def test_pin_opens_a_pr_and_leaves_dev(self):
        self.update = "pin"
        self.record()
        self.run_bump("main", self.b)
        self.assertEqual(self.gitlink("main"), self.a)
        self.assertEqual(self.prs[0]["base"], "main")
        self.assertEqual(self.gitlink(self.prs[0]["head"]), self.b)

    def test_unknown_commit_or_source_is_refused(self):
        self.record()
        with self.assertRaises(SystemExit):
            self.run_bump("main", "f" * 40)

        class A:
            app, source, branch, sha, actor, server = "x", "o/other", "main", self.b, "", self.server
        with self.assertRaises(SystemExit):
            cicd.bump(self.root, A)


if __name__ == "__main__":
    unittest.main()


class Detect(unittest.TestCase):
    def setUp(self):
        import wrap  # noqa: PLC0415
        self.wrap = wrap
        self.src = Path(tempfile.mkdtemp())

    def put(self, name, text="x"):
        p = self.src / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)

    def kind(self):
        return self.wrap.detect(self.src)

    def test_own_dockerfile_wins(self):
        self.put("Dockerfile", "FROM x\nEXPOSE 9000\n")
        self.put("index.html")
        d = self.kind()
        self.assertEqual((d["kind"], d["dockerfile"], d["port"]), ("own", "src/Dockerfile", 9000))

    def test_static_site_in_public(self):
        self.put("public/index.html")
        d = self.kind()
        self.assertEqual((d["kind"], d["port"], d["run_as"]), ("static", 8080, 101))
        self.assertIn("COPY --chown=101:101 public/", d["text"])

    def test_python_and_node_and_nothing(self):
        self.put("requirements.txt")
        self.assertEqual(self.kind()["kind"], "none")          # no entry point to run
        self.put("app.py")
        self.assertIn('CMD ["python", "app.py"]', self.kind()["text"])
        other = Path(tempfile.mkdtemp())
        (other / "package.json").write_text('{"scripts": {"start": "node s.js"}}')
        self.assertEqual(self.wrap.detect(other)["kind"], "node")

    def test_generated_files(self):
        self.put("index.html")
        work = Path(tempfile.mkdtemp())
        made = self.wrap.generate(work, "demo", "o/demo-src", self.kind(), "follow")
        cfg = yaml.safe_load((work / "cicd.yaml").read_text())
        self.assertEqual(cfg["spec"]["build"], {"context": "src", "dockerfile": "Dockerfile"})
        dep = yaml.safe_load((work / "deploy/deployment.yaml").read_text())
        self.assertEqual(dep["spec"]["template"]["spec"]["securityContext"]["runAsUser"], 101)
        self.assertEqual(dep["spec"]["template"]["spec"]["containers"][0]["ports"][0]["containerPort"], 8080)
        self.assertIn("Dockerfile (static)", made)
