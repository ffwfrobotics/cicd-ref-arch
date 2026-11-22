"""Fixture repos: developers' repos in ffwf-fixtures, IaC roots in ffwf-iac, made (and reset) from what is written here."""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from pathlib import Path

import run as e2e

ORG = "ffwf-fixtures"   # developers' repos: CI/CD only reads them
IAC = "ffwf-iac"        # IaC roots (monorepos that hold them, direct apps, stacks): CI/CD's own (tenants/_writable.yaml)

# fx-vibe: what a vibe-coded repo looks like from here. A static site with no Dockerfile, no tests,
# and a deploy/ that would never work (wrong image, no probes, a namespace): wrapping must ignore it.
VIBE = {
    "index.html": "<!doctype html><title>fx-vibe</title><h1>fx-vibe</h1><p id=marker>{marker}</p>\n",
    "deploy/kustomization.yaml": "resources: [deployment.yaml]\n",
    "deploy/deployment.yaml": ("apiVersion: apps/v1\nkind: Deployment\nmetadata: {name: vibe, namespace: prod}\n"
                               "spec:\n  replicas: 5\n  selector: {matchLabels: {app: vibe}}\n"
                               "  template:\n    metadata: {labels: {app: vibe}}\n"
                               "    spec: {containers: [{name: vibe, image: 'nginx:latest'}]}\n"),
    "README.md": "# fx-vibe\n\nA fixture for cicd-ref-arch's wrapped mode (tests/e2e).\n",
}


def ensure_repo(name: str, private: bool = False, org: str = ORG) -> str:
    repo = f"{org}/{name}"
    code, _ = e2e.api("GET", f"/repos/{repo}")
    if code == 404:
        code, out = e2e.api("POST", f"/orgs/{org}/repos", {"name": name, "private": private, "auto_init": False,
                                                            "default_branch": "main"})
        if code not in (200, 201):
            raise e2e.Fail(f"could not create {repo}: {code} {out}")
    return repo


def write_tree(repo: str, files: dict[str, str], message: str, branch: str = "main", reset: bool = False) -> str:
    """Commit files to a branch (reset: the branch holds exactly these files). Returns the commit."""
    d = Path(tempfile.mkdtemp(prefix="fx-"))
    try:
        url = f"{e2e.SERVER}/{repo}.git"
        r = subprocess.run(["git", "-c", f"http.extraHeader={e2e.auth()}", "clone", "-q", url, str(d)], capture_output=True)
        if r.returncode != 0 or not (d / ".git").exists():
            d.mkdir(exist_ok=True)
            e2e.git(d, "init", "-q", "-b", branch)
        else:
            has = e2e.git(d, "ls-remote", "--heads", "origin", branch)
            if has:
                e2e.git(d, "checkout", "-q", "-B", branch, f"origin/{branch}")
            else:
                e2e.git(d, "checkout", "-q", *(["--orphan", branch] if reset else ["-B", branch]))
        if reset:
            for p in d.iterdir():
                if p.name != ".git":
                    shutil.rmtree(p) if p.is_dir() else p.unlink()
        for path, text in files.items():
            p = d / path
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(text)
        e2e.git(d, "add", "-A")
        if not e2e.git(d, "status", "--porcelain"):
            return e2e.git(d, "rev-parse", "HEAD")
        e2e.git(d, "commit", "-q", "-m", message)
        e2e.git(d, "push", "-q", *(["-f"] if reset else []), url, f"HEAD:refs/heads/{branch}")
        return e2e.git(d, "rev-parse", "HEAD")
    finally:
        shutil.rmtree(d, ignore_errors=True)


def delete_branch(repo: str, branch: str):
    e2e.api("DELETE", f"/repos/{repo}/branches/{branch}")


def vibe(marker: str) -> dict[str, str]:
    return {k: v.replace("{marker}", marker) for k, v in VIBE.items()}


SVC_A = {"index.html": "<!doctype html><title>svc-a</title><p id=marker>{marker}</p>\n"}
SVC_B = {
    "main.py": ("import http.server, os\n\n"
                "class H(http.server.BaseHTTPRequestHandler):\n"
                "    def do_GET(self):\n"
                "        body = b'svc-b {marker}'\n"
                "        self.send_response(200); self.send_header('Content-Length', str(len(body))); self.end_headers()\n"
                "        self.wfile.write(body)\n\n"
                "http.server.ThreadingHTTPServer(('0.0.0.0', int(os.environ.get('PORT', '8000'))), H).serve_forever()\n"),
    "requirements.txt": "# no dependencies\n",
}


def fill(files: dict[str, str], marker: str) -> dict[str, str]:
    return {k: v.replace("{marker}", marker) for k, v in files.items()}


def iac_files(app: str, source_dir: Path, context: str) -> dict[str, str]:
    """An IaC root's files for a source checked out at source_dir, built with `context` (wrap's generator)."""
    import sys
    sys.path.insert(0, str(e2e.ROOT / "tools"))
    import wrap  # noqa: PLC0415
    d = wrap.detect(source_dir)
    d["context"] = context
    if d["kind"] == "own":
        d["dockerfile"] = f"{context}/Dockerfile"
    work = Path(tempfile.mkdtemp(prefix="iac-"))
    wrap.generate(work, app, str(source_dir), d, "follow")
    if d["text"] is None:
        (work / "Dockerfile").unlink(missing_ok=True)
    out = {}
    for p in work.rglob("*"):
        if p.is_file() and p.name != "README.md":
            out[str(p.relative_to(work))] = p.read_text()
    shutil.rmtree(work)
    return out


def write_with_submodules(repo: str, files: dict[str, str], subs: dict[str, tuple[str, str]], message: str) -> str:
    """Reset a repo's main to `files` plus submodules {path: (repo on this forge, commit)}, with relative URLs."""
    d = Path(tempfile.mkdtemp(prefix="fx-"))
    try:
        e2e.git(d, "init", "-q", "-b", "main")
        gm = []
        for path, (sub, sha) in subs.items():
            rel = os.path.relpath(f"/{sub}.git", f"/{repo}")
            gm.append(f'[submodule "{path}"]\n\tpath = {path}\n\turl = {rel}\n\tbranch = main\n')
        (d / ".gitmodules").write_text("".join(gm))
        for path, text in files.items():
            p = d / path
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(text)
        e2e.git(d, "add", "-A")
        # the gitlinks last: `add -A` would record a submodule with no checkout as deleted
        for path, (sub, sha) in subs.items():
            e2e.git(d, "update-index", "--add", "--cacheinfo", f"160000,{sha},{path}")
        e2e.git(d, "commit", "-q", "-m", message)
        for path in subs:
            if not e2e.git(d, "ls-tree", "HEAD", path):
                raise e2e.Fail(f"{repo}: submodule {path} is not in the commit")
        e2e.git(d, "push", "-q", "-f", f"{e2e.SERVER}/{repo}.git", "HEAD:refs/heads/main")
        return e2e.git(d, "rev-parse", "HEAD")
    finally:
        shutil.rmtree(d, ignore_errors=True)


def source_dir(files: dict[str, str]) -> Path:
    d = Path(tempfile.mkdtemp(prefix="src-"))
    for k, v in files.items():
        (d / k).parent.mkdir(parents=True, exist_ok=True)
        (d / k).write_text(v)
    return d


def hook(repo: str):
    """A push webhook to the dev dashboard (fixtures test what dev runs)."""
    secret = os.environ.get("CICD_HOOK_SECRET") or ""
    if not secret:
        raise e2e.Fail("CICD_HOOK_SECRET is not set")
    code, hooks = e2e.api("GET", f"/repos/{repo}/hooks")
    cfg = {"url": e2e.DEV_HOOK, "content_type": "json", "secret": secret}
    same = [h for h in (hooks if code == 200 else []) if (h.get("config") or {}).get("url") == e2e.DEV_HOOK]
    if same:
        e2e.api("PATCH", f"/repos/{repo}/hooks/{same[0]['id']}", {"active": True, "events": ["push", "delete"], "config": cfg})
    else:
        e2e.api("POST", f"/repos/{repo}/hooks", {"type": "forgejo", "active": True, "events": ["push", "delete"],
                                                 "branch_filter": "*", "config": cfg})
