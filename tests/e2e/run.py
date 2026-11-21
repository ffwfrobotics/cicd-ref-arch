#!/usr/bin/env python3
"""End-to-end scenarios against the live platform (Plan 5, docs/enrollment.md, docs/stacks.md).

  FORGEJO_TOKEN=<the bot's token> tests/e2e/run.py <scenario>... | --list

Each scenario acts as the bot (pushes, dispatches), waits for what the platform records (pipeline
runs, envs/<cluster>/<app>/... in the state repo, commit statuses) and asserts states and fields,
never wording. Exit 0 when every scenario passed. Fixtures live in the org ffwf-fixtures and are
made (and reset) by tests/e2e/fixtures.py.
"""
from __future__ import annotations

import base64
import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import yaml

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent.parent / "tools"))
import cicd  # noqa: E402

SERVER = os.environ.get("FORGEJO_URL", "https://forge.goblincorps.com")
STATE = os.environ.get("STATE_REPO", "ffwf/cicd-ref-arch")
CLUSTER = os.environ.get("CLUSTER", "c-local")
TOKEN = os.environ.get("FORGEJO_TOKEN", "")
BOT = os.environ.get("BOT", "ffwfbot")
SCENARIOS: dict[str, callable] = {}


def scenario(fn):
    SCENARIOS[fn.__name__.replace("_", "-")] = fn
    return fn


class Fail(Exception):
    pass


def check(cond, what):
    if not cond:
        raise Fail(what)
    print(f"  ok  {what}")


def api(method, path, body=None):
    code, out = cicd.api(method, SERVER, path, TOKEN, body)
    return code, out


def wait(what, fn, timeout=900, every=10):
    """Poll fn() until it returns something truthy; that value is returned."""
    t0 = time.time()
    while time.time() - t0 < timeout:
        v = fn()
        if v:
            print(f"  ..  {what} ({time.time() - t0:.0f}s)")
            return v
        time.sleep(every)
    raise Fail(f"timed out waiting for {what} ({timeout}s)")


def auth():
    return "AUTHORIZATION: basic " + base64.b64encode(f"{BOT}:{TOKEN}".encode()).decode()


def git(cwd, *a, check=True):
    return subprocess.run(["git", "-c", f"http.extraHeader={auth()}", "-c", "user.name=cicd-e2e",
                           "-c", "user.email=cicd-e2e@noreply.invalid", "-C", str(cwd), *a],
                          capture_output=True, text=True, check=check).stdout.strip()


def clone(repo) -> Path:
    d = Path(tempfile.mkdtemp(prefix="e2e-"))
    subprocess.run(["git", "-c", f"http.extraHeader={auth()}", "clone", "-q", f"{SERVER}/{repo}.git", str(d)], check=True)
    return d


def head(repo, branch) -> str:
    code, b = api("GET", f"/repos/{repo}/branches/{branch}")
    return b["commit"]["id"] if code == 200 else ""


def dispatch(**inputs):
    code, out = api("POST", f"/repos/{STATE}/actions/workflows/pipeline.yaml/dispatches",
                    {"ref": "master", "inputs": {k: str(v) for k, v in inputs.items()}})
    if code not in (200, 201, 204):
        raise Fail(f"dispatch failed: {code} {out}")


def run_for(app, sha, action="deploy"):
    """The newest pipeline run for app/sha/action: {status, url} (or None)."""
    code, d = api("GET", f"/repos/{STATE}/actions/runs?workflow_id=pipeline.yaml&limit=50")
    for r in sorted((d or {}).get("workflow_runs") or [], key=lambda r: r.get("index_in_repo", 0), reverse=True):
        inp = json.loads(r.get("event_payload") or "{}").get("inputs") or {}
        if inp.get("app") == app and inp.get("sha") == sha and (inp.get("action") or "deploy") == action:
            return {"status": r["status"], "url": r.get("html_url"), "id": r["id"]}
    return None


def finished(app, sha, action="deploy", timeout=1200):
    r = wait(f"pipeline run for {app} {sha[:7]} ({action}) to finish",
             lambda: (lambda x: x if x and x["status"] not in ("running", "waiting", "queued", "blocked") else None)(
                 run_for(app, sha, action)), timeout=timeout)
    return r


def env_meta(app, env_dir):
    code, raw = api("GET", f"/repos/{STATE}/raw/envs/{CLUSTER}/{app}/{env_dir}/cicd-env.yaml?ref=master")
    if code != 200:
        return None
    return raw if isinstance(raw, dict) else None


def env_meta_text(app, env_dir):
    req = __import__("urllib.request").request.Request(
        f"{SERVER}/api/v1/repos/{STATE}/raw/envs/{CLUSTER}/{app}/{env_dir}/cicd-env.yaml?ref=master",
        headers={"Authorization": f"token {TOKEN}"})
    try:
        with __import__("urllib.request").request.urlopen(req, timeout=30) as r:
            return yaml.safe_load(r.read())
    except Exception:
        return None


def status(repo, sha, context):
    code, d = api("GET", f"/repos/{repo}/commits/{sha}/statuses?limit=50")
    hits = [s for s in (d or []) if s.get("context") == context]
    return max(hits, key=lambda s: s["id"])["status"] if hits else None


def deployed(app, env_dir, sha, repo, timeout=1500):
    """Wait until the environment runs sha and its runtime check has a result: (meta, runtime state)."""
    meta = wait(f"{app}/{env_dir} to run {sha[:7]}",
                lambda: (lambda m: m if m and m.get("commit") == sha else None)(env_meta_text(app, env_dir)), timeout=timeout)
    rt = wait(f"cicd/runtime on {repo}@{sha[:7]}",
              lambda: (lambda s: s if s in ("success", "failure", "error") else None)(status(repo, sha, "cicd/runtime")),
              timeout=600)
    return meta, rt


# ---------------------------------------------------------------- scenarios


@scenario
def v1_direct():
    """intake-sample (direct): its head redeploys to dev and runs, unchanged by modes."""
    app, repo = "intake-sample", "ffwfbot/intake-sample"
    t = cicd.tenant_spec(yaml.safe_load(raw_state(f"tenants/{app}.yaml")))
    check(t["mode"] == "direct" and not t["sources"], "the tenant record reads as direct")
    code, r = api("GET", f"/repos/{repo}")
    sha = head(repo, r["default_branch"])
    dispatch(app=app, branch=r["default_branch"], sha=sha, action="deploy", actor="cicd-e2e")
    run = finished(app, sha)
    check(run["status"] == "success", f"the pipeline run succeeded ({run['url']})")
    meta, rt = deployed(app, "dev", sha, repo)
    check(meta.get("commit") == sha and "sources" not in meta, "dev records the commit and no sources")
    check(rt == "success", "cicd/runtime: running")


def raw_state(path):
    req = __import__("urllib.request").request.Request(f"{SERVER}/api/v1/repos/{STATE}/raw/{path}?ref=master",
                                                       headers={"Authorization": f"token {TOKEN}"})
    with __import__("urllib.request").request.urlopen(req, timeout=30) as r:
        return r.read().decode()


def main():
    args = sys.argv[1:]
    if not args or args == ["--list"]:
        for name, fn in SCENARIOS.items():
            print(f"{name:16} {fn.__doc__.strip().splitlines()[0]}")
        return 0
    if not TOKEN:
        sys.exit("FORGEJO_TOKEN is not set")
    failed = []
    for name in args:
        fn = SCENARIOS.get(name) or sys.exit(f"no scenario {name}")
        print(f"== {name}: {fn.__doc__.strip().splitlines()[0]}")
        try:
            fn()
            print(f"PASS {name}")
        except (Fail, subprocess.CalledProcessError) as e:
            print(f"FAIL {name}: {e}")
            failed.append(name)
    print(f"{len(args) - len(failed)}/{len(args)} passed" + (f"; failed: {', '.join(failed)}" if failed else ""))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
