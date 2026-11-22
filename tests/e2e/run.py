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


DEV_HOOK = os.environ.get("E2E_HOOK_URL", "https://dashboard-dev.c-local.k.ffwf.net/hooks/forge")
ROOT = HERE.parent.parent


def platform_change(message, fn):
    """Clone the platform repo, let fn(root) change it, commit and push (retrying on a concurrent push)."""
    for attempt in range(5):
        d = clone(STATE)
        fn(d)
        subprocess.run([sys.executable, str(ROOT / "tools/cicd.py"), "--root", str(d), "index", "--cluster", CLUSTER],
                       check=True, capture_output=True)
        git(d, "add", "-A")
        if not git(d, "status", "--porcelain"):
            return
        git(d, "commit", "-q", "-m", message)
        if subprocess.run(["git", "-c", f"http.extraHeader={auth()}", "-C", str(d), "push", "-q", "origin", "HEAD:master"],
                          capture_output=True).returncode == 0:
            return
        time.sleep(3 * (attempt + 1))
    raise Fail("could not push to the platform repo")


def unenroll(app, iac=None):
    """Remove an app's tenant record and environments, and its IaC repo: a clean start for a scenario."""
    def drop(d):
        for p in (d / "tenants" / f"{app}.yaml", d / "envs" / CLUSTER / app):
            if p.is_dir():
                __import__("shutil").rmtree(p)
            elif p.exists():
                p.unlink()
    platform_change(f"e2e: unenroll {app}", drop)
    if iac:
        api("DELETE", f"/repos/{iac}")


def enroll_wrapped(app, source, update="follow"):
    def wrap(d):
        env = dict(os.environ, FORGEJO_TOKEN=TOKEN, BOT=BOT)
        r = subprocess.run([sys.executable, str(ROOT / "tools/wrap.py"), "--app", app, "--source", source, "--update", update,
                            "--approved", "--hook-url", DEV_HOOK, "--requested-by", "cicd-e2e", "--root", str(d),
                            "--server", SERVER], env=env, capture_output=True, text=True)
        print("\n".join("      " + x for x in (r.stdout + r.stderr).strip().splitlines()))
        if r.returncode != 0:
            raise Fail(f"wrap failed: {r.stderr.strip()[-300:]}")
    platform_change(f"e2e: wrap {source} as {app}", wrap)


def fetch(url):
    import ssl
    import urllib.request
    ctx = ssl.create_default_context()
    ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE      # the cluster CA isn't in this trust store
    try:
        with urllib.request.urlopen(url, timeout=60, context=ctx) as r:
            return r.status, r.read().decode(errors="replace")
    except Exception as e:
        return 0, str(e)


def iac_head(iac, branch="main"):
    code, c = api("GET", f"/repos/{iac}/commits?sha={branch}&limit=1")
    return c[0] if code == 200 and c else None


@scenario
def v3_wrapped_follow():
    """fx-vibe wrapped (follow): IaC repo owns build and deploy; a source push bumps and redeploys; branches map."""
    import fixtures
    app, iac = "fxw", "ffwf-iac/fxw"
    src = fixtures.ensure_repo("fx-vibe")
    unenroll(app, iac)
    m1 = f"m1-{int(time.time())}"
    s1 = fixtures.write_tree(src, fixtures.vibe(m1), f"fixture: {m1}", reset=True)
    enroll_wrapped(app, src)
    head1 = iac_head(iac)
    check(head1 and f"Source-Commit: {s1}" in head1["commit"]["message"], "the IaC repo's first commit pins the source head")
    code, tree = api("GET", f"/repos/{iac}/git/trees/main?recursive=1")
    names = {x["path"] for x in tree["tree"]}
    check({"Dockerfile", "cicd.yaml", "deploy/deployment.yaml", "src"} <= names, "Dockerfile, cicd.yaml, deploy/ and src are in the IaC repo")
    # the IaC push happened before the tenant record existed: start its first run, as the environments workflow would
    dispatch(app=app, branch="main", sha=head1["sha"], action="deploy", actor="cicd-e2e")
    run = finished(app, head1["sha"])
    check(run["status"] == "success", f"the first build succeeded ({run['url']})")
    meta, rt = deployed(app, "dev", head1["sha"], iac)
    check(meta.get("sources") == [{"path": "src", "repo": src, "commit": s1}], "dev records the source commit it runs")
    check(rt == "success", "cicd/runtime: running")
    host = meta["hosts"][0]
    code, body = wait(f"{host} to serve {m1}", lambda: (lambda r: r if m1 in r[1] else None)(fetch(f"https://{host}/")), timeout=300)
    check(code == 200, f"https://{host}/ serves the source's page")
    code, dep = api("GET", f"/repos/{iac}/raw/deploy/deployment.yaml")
    check("replicas" not in str(dep) and "namespace: prod" not in str(dep), "the source's own deploy/ is not what runs")

    # a push to the source: the webhook bumps the IaC repo, which redeploys
    m2 = f"m2-{int(time.time())}"
    s2 = fixtures.write_tree(src, fixtures.vibe(m2), f"fixture: {m2}")
    head2 = wait("the bump commit in the IaC repo",
                 lambda: (lambda h: h if h and f"Source-Commit: {s2}" in h["commit"]["message"] else None)(iac_head(iac)), timeout=600)
    check("Requested-by:" in head2["commit"]["message"], "the bump names who pushed")
    meta, rt = deployed(app, "dev", head2["sha"], iac)
    check(meta.get("sources", [{}])[0].get("commit") == s2 and rt == "success", "dev runs the new source commit")
    wait(f"{host} to serve {m2}", lambda: m2 in fetch(f"https://{host}/")[1], timeout=300)
    check(True, "the new page is served")

    # a source branch: its own IaC branch and branch environment; deleting it removes both
    s3 = fixtures.write_tree(src, fixtures.vibe("m3-branch"), "fixture: branch", branch="feat-x")
    bh = wait("IaC branch src/feat-x", lambda: (lambda h: h if h and f"Source-Commit: {s3}" in h["commit"]["message"] else None)(
        iac_head(iac, "src/feat-x")), timeout=600)
    env_dir = "branch-" + cicd.branch_slug(app, "src/feat-x")
    meta, rt = deployed(app, env_dir, bh["sha"], iac)
    check(meta.get("sources", [{}])[0].get("commit") == s3, f"{env_dir} runs the branch's source commit")
    fixtures.delete_branch(src, "feat-x")
    wait("IaC branch src/feat-x to be removed", lambda: api("GET", f"/repos/{iac}/branches/src/feat-x")[0] == 404, timeout=600)
    wait(f"{env_dir} to be removed", lambda: env_meta_text(app, env_dir) is None, timeout=900, every=20)
    check(True, "the branch environment is gone")


@scenario
def v4_wrapped_pin():
    """fx-vibe-pin wrapped (pin): a source push opens a bump PR; dev doesn't move until it is merged."""
    import fixtures
    app, iac = "fxp", "ffwf-iac/fxp"
    src = fixtures.ensure_repo("fx-vibe-pin")
    unenroll(app, iac)
    s1 = fixtures.write_tree(src, fixtures.vibe("p1"), "fixture: p1", reset=True)
    enroll_wrapped(app, src, update="pin")
    head1 = iac_head(iac)
    dispatch(app=app, branch="main", sha=head1["sha"], action="deploy", actor="cicd-e2e")
    meta, rt = deployed(app, "dev", head1["sha"], iac)
    check(meta["sources"][0]["commit"] == s1 and rt == "success", "dev runs the wrapped source")
    s2 = fixtures.write_tree(src, fixtures.vibe("p2"), "fixture: p2")
    pr = wait("a bump PR in the IaC repo", lambda: next((p for p in api("GET", f"/repos/{iac}/pulls?state=open")[1] or []
                                                         if s2[:7] in p["title"]), None), timeout=600)
    check(iac_head(iac)["sha"] == head1["sha"], "main has not moved")
    time.sleep(60)
    check((env_meta_text(app, "dev") or {}).get("commit") == head1["sha"], "dev still runs the old commit")
    code, _ = api("POST", f"/repos/{iac}/pulls/{pr['number']}/merge", {"Do": "merge", "MergeTitleField": pr["title"]})
    check(code in (200, 204), f"merged PR #{pr['number']}")
    head2 = wait("main to have the merge", lambda: (lambda h: h if h["sha"] != head1["sha"] else None)(iac_head(iac)), timeout=120)
    meta, rt = deployed(app, "dev", head2["sha"], iac)
    check(meta["sources"][0]["commit"] == s2 and rt == "success", "after the merge dev runs the new source")


def enroll_record(app, spec):
    def put(d):
        t = {"apiVersion": cicd.API, "kind": "Tenant", "metadata": {"name": app},
             "spec": {"tenant": "ffwf", "clusters": [CLUSTER], "enrolled": time.strftime("%Y-%m-%d"), **spec}}
        cicd.tenant_spec(t)
        (d / "tenants" / f"{app}.yaml").write_text("# e2e fixture\n" + yaml.safe_dump(t, sort_keys=False))
    platform_change(f"e2e: enroll {app}", put)


def mono_sources():
    import fixtures
    a, b = fixtures.ensure_repo("fx-svc-a"), fixtures.ensure_repo("fx-svc-b")
    sa = fixtures.write_tree(a, fixtures.fill(fixtures.SVC_A, "a1"), "fixture: a1", reset=True)
    sb = fixtures.write_tree(b, fixtures.fill(fixtures.SVC_B, "b1"), "fixture: b1", reset=True)
    for r in (a, b):
        fixtures.hook(r)
    return (a, sa), (b, sb)


def check_mono(apps, repo):
    """Each app of a monorepo deploys from the monorepo head and serves its own source."""
    h = head(repo, "main")
    for app, marker in apps:
        dispatch(app=app, branch="main", sha=h, action="deploy", actor="cicd-e2e")
    hosts = {}
    for app, marker in apps:
        meta, rt = deployed(app, "dev", h, repo)
        check(rt == "success" and meta.get("sources"), f"{app}: dev runs, with its sources recorded")
        hosts[app] = meta["hosts"][0]
        wait(f"{hosts[app]} to serve {marker}", lambda: marker in fetch(f"https://{hosts[app]}/")[1], timeout=300)
        check(True, f"{app} serves its own source")
    return hosts


@scenario
def v5_monorepo():
    """fx-mono: one repo, two projects (apps/a static, apps/b Python) built from submodules svc-a, svc-b."""
    import fixtures
    (a, sa), (b, sb) = mono_sources()
    repo = fixtures.ensure_repo("fx-mono")
    for app in ("fxm-a", "fxm-b"):
        unenroll(app)
    files = {f"apps/a/{k}": v for k, v in fixtures.iac_files("fxm-a", fixtures.source_dir(fixtures.fill(fixtures.SVC_A, "a1")), "../../svc-a").items()}
    files.update({f"apps/b/{k}": v for k, v in fixtures.iac_files("fxm-b", fixtures.source_dir(fixtures.fill(fixtures.SVC_B, "b1")), "../../svc-b").items()})
    files["README.md"] = "# fx-mono\n\nA monorepo fixture: projects in apps/, code in submodules.\n"
    fixtures.write_with_submodules(repo, files, {"svc-a": (a, sa), "svc-b": (b, sb)}, "fixture: monorepo")
    fixtures.hook(repo)
    enroll_record("fxm-a", {"mode": "monorepo", "repo": repo, "path": "apps/a", "sources": [{"path": "svc-a", "repo": a}]})
    enroll_record("fxm-b", {"mode": "monorepo", "repo": repo, "path": "apps/b", "sources": [{"path": "svc-b", "repo": b}]})
    hosts = check_mono([("fxm-a", "a1"), ("fxm-b", "b1")], repo)
    # a push to svc-a bumps the monorepo; both projects redeploy from the new monorepo commit, a serves a2
    sa2 = fixtures.write_tree(a, fixtures.fill(fixtures.SVC_A, "a2"), "fixture: a2")
    h2 = wait("the monorepo bump", lambda: (lambda c: c if c and f"Source-Commit: {sa2}" in c["commit"]["message"] else None)(
        iac_head(repo)), timeout=600)
    meta, rt = deployed("fxm-a", "dev", h2["sha"], repo)
    check(meta["sources"][0]["commit"] == sa2 and rt == "success", "fxm-a runs svc-a's new commit")
    wait("a2 to be served", lambda: "a2" in fetch(f"https://{hosts['fxm-a']}/")[1], timeout=300)
    check(True, "fxm-a serves a2")


@scenario
def v6_monorepo_config_repo():
    """fx-mono-cfg: the IaC roots live in a config repo that is itself a submodule; pushes to it bump it."""
    import fixtures
    (a, sa), (b, sb) = mono_sources()
    cfg = fixtures.ensure_repo("fx-config")
    repo = fixtures.ensure_repo("fx-mono-cfg")
    for app in ("fxc-a", "fxc-b"):
        unenroll(app)
    files = {f"apps/a/{k}": v for k, v in fixtures.iac_files("fxc-a", fixtures.source_dir(fixtures.fill(fixtures.SVC_A, "a1")), "../../../svc-a").items()}
    files.update({f"apps/b/{k}": v for k, v in fixtures.iac_files("fxc-b", fixtures.source_dir(fixtures.fill(fixtures.SVC_B, "b1")), "../../../svc-b").items()})
    sc = fixtures.write_tree(cfg, files, "fixture: config", reset=True)
    fixtures.hook(cfg)
    fixtures.write_with_submodules(repo, {"README.md": "# fx-mono-cfg\n"}, {"svc-a": (a, sa), "svc-b": (b, sb), "config": (cfg, sc)},
                                   "fixture: monorepo with a config repo")
    fixtures.hook(repo)
    for app, p, s in (("fxc-a", "a", a), ("fxc-b", "b", b)):
        enroll_record(app, {"mode": "monorepo", "repo": repo, "path": f"config/apps/{p}",
                            "sources": [{"path": f"svc-{p}", "repo": s}, {"path": "config", "repo": cfg}]})
    check_mono([("fxc-a", "a1"), ("fxc-b", "b1")], repo)
    # a config change (more memory for b): both apps' bumps of `config` land as one commit, b redeploys with it
    code, dep = api("GET", f"/repos/{cfg}/raw/apps/b/deploy/deployment.yaml")
    sc2 = fixtures.write_tree(cfg, {"apps/b/deploy/deployment.yaml": dep.replace("memory: 32Mi", "memory: 48Mi")}, "fixture: b gets 48Mi")
    h2 = wait("the config bump", lambda: (lambda c: c if c and f"Source-Commit: {sc2}" in c["commit"]["message"] else None)(
        iac_head(repo)), timeout=600)
    meta, rt = deployed("fxc-b", "dev", h2["sha"], repo)
    srcs = {x["path"]: x["commit"] for x in meta["sources"]}
    check(srcs.get("config") == sc2 and rt == "success", "fxc-b runs the new config")
    code, app_yaml = api("GET", f"/repos/{STATE}/raw/envs/{CLUSTER}/fxc-b/dev/app.yaml")
    check("48Mi" in str(app_yaml), "the rendered environment has the new request")


def overlay_files(marker, prod_patch, app="fxo"):
    """fx-overlays: a direct app whose deploy-prod/ asks for more memory than dev."""
    import fixtures
    files = fixtures.iac_files(app, fixtures.source_dir(fixtures.fill(fixtures.SVC_A, marker)), ".")
    files.update(fixtures.fill(fixtures.SVC_A, marker))
    cfg = yaml.safe_load(files["cicd.yaml"])
    cfg["spec"]["overlays"] = {"allow": ["resources"]}
    files["cicd.yaml"] = yaml.safe_dump(cfg, sort_keys=False)
    files["deploy-prod/kustomization.yaml"] = yaml.safe_dump({
        "apiVersion": "kustomize.config.k8s.io/v1beta1", "kind": "Kustomization", "resources": ["../deploy"],
        "patches": [{"target": {"kind": "Deployment", "name": app}, "patch": prod_patch}]})
    return files


BIGGER = "- op: replace\n  path: /spec/template/spec/containers/0/resources/requests/memory\n  value: 128Mi\n"
BROKEN = "- op: replace\n  path: /spec/template/spec/nonsense/0/x\n  value: 1\n"


@scenario
def v2_overlays():
    """fx-overlays (direct): dev runs the base, prod the deploy-prod/ overlay; the PR shows it; a broken overlay fails the push."""
    import fixtures
    app, repo = "fxo", fixtures.ensure_repo("fx-overlays")
    unenroll(app)
    enroll_record(app, {"repo": repo})
    fixtures.hook(repo)
    s1 = fixtures.write_tree(repo, overlay_files("o1", BIGGER), "fixture: overlays", reset=True)
    dispatch(app=app, branch="main", sha=s1, action="deploy", actor="cicd-e2e")
    meta, rt = deployed(app, "dev", s1, repo)
    check(rt == "success", "dev runs")
    dev_yaml = raw_state(f"envs/{CLUSTER}/{app}/dev/app.yaml")
    prod_yaml = raw_state(f"envs/{CLUSTER}/{app}/dev/app-prod.yaml")
    check("32Mi" in dev_yaml and "128Mi" not in dev_yaml, "dev runs the base's 32Mi request")
    check("128Mi" in prod_yaml, "dev keeps the prod overlay built from the same commit")
    dispatch(app=app, branch="main", sha=s1, action="request-promotion", actor="cicd-e2e")
    pr = wait("the promotion PR", lambda: next((p for p in api("GET", f"/repos/{STATE}/pulls?state=open&limit=20")[1] or []
                                               if p["head"]["ref"].startswith(f"promote/{app}-prod-")), None), timeout=600)
    check("Prod differs from dev" in pr["body"] and "+" in pr["body"] and "128Mi" in pr["body"], "the PR shows prod's bigger request")
    code, _ = api("POST", f"/repos/{STATE}/pulls/{pr['number']}/merge", {"Do": "merge", "MergeTitleField": pr["title"]})
    check(code in (200, 204), f"merged promotion PR #{pr['number']}")
    wait("prod to be applied", lambda: (env_meta_text(app, "prod") or {}).get("commit") == s1, timeout=900, every=20)
    check("128Mi" in raw_state(f"envs/{CLUSTER}/{app}/prod/app.yaml"), "prod runs the overlay's 128Mi request")
    code, ev = api("GET", f"/repos/{STATE}/raw/envs/{CLUSTER}/{app}/prod/evidence/approval.json")
    check(isinstance(ev, dict) and ev.get("separated") is False, "the approval record says no second person (the bot did both)")
    s2 = fixtures.write_tree(repo, overlay_files("o2", BROKEN), "fixture: a broken prod overlay")
    st = wait("cicd/contract/overlays on the broken commit",
              lambda: (lambda x: x if x in ("failure", "error", "warning") else None)(status(repo, s2, "cicd/contract/overlays")), timeout=900)
    check(st in ("failure", "error"), f"the broken prod overlay fails the push ({st})")
    time.sleep(60)
    check((env_meta_text(app, "dev") or {}).get("commit") == s1, "dev was not redeployed from the broken commit")
    unenroll(app)


def push_image(src, tag):
    """Put a local docker image into c-local's registry as fx-prebuilt:<tag> (the host side of the registry)."""
    for cmd in (["docker", "pull", "-q", src], ["docker", "tag", src, f"127.0.0.1:5003/fx-prebuilt:{tag}"],
                ["docker", "push", "-q", f"127.0.0.1:5003/fx-prebuilt:{tag}"]):
        subprocess.run(cmd, check=True, capture_output=True)
    r = subprocess.run(["docker", "inspect", f"127.0.0.1:5003/fx-prebuilt:{tag}", "--format", "{{index .RepoDigests 0}}"],
                       capture_output=True, text=True, check=True)
    return r.stdout.strip().rsplit("@", 1)[1]


def dispatch_enroll(**inputs):
    code, out = api("POST", f"/repos/{STATE}/actions/workflows/enroll.yaml/dispatches",
                    {"ref": "master", "inputs": {k: str(v) for k, v in inputs.items()}})
    if code not in (200, 201, 204):
        raise Fail(f"enroll dispatch failed: {code} {out}")


def approve(app):
    def ok(d):
        p = d / "tenants" / f"{app}.yaml"
        t = yaml.safe_load(p.read_text())
        t["spec"]["status"] = "approved"
        p.write_text(yaml.safe_dump(t, sort_keys=False))
    platform_change(f"e2e: approve {app}", ok)


@scenario
def vp_prebuilt():
    """fx-prebuilt (prebuilt, via the enroll workflow): an existing image deploys with an SBOM; a moved tag is followed."""
    app, iac = "fxb", "ffwf-iac/fxb"
    unenroll(app, iac)
    d1 = push_image("docker.io/nginxinc/nginx-unprivileged:1.29-alpine", "stable")
    ref = "registry.buildkit.svc.cluster.local:5000/fx-prebuilt:stable"      # as the runners see c-local's registry
    dispatch_enroll(app=app, mode="prebuilt", image=ref, update="follow", actor="cicd-e2e", hook_url=DEV_HOOK)
    wait("the enroll workflow to write tenants/fxb.yaml", lambda: api("GET", f"/repos/{STATE}/contents/tenants/{app}.yaml")[0] == 200, timeout=600)
    t = cicd.tenant_spec(yaml.safe_load(raw_state(f"tenants/{app}.yaml")))
    check(t["mode"] == "prebuilt" and t.get("status") == "pending", "enrolled as prebuilt, pending")
    code, cfg = api("GET", f"/repos/{iac}/raw/cicd.yaml")
    spec = yaml.safe_load(cfg)["spec"]
    check(spec["image"]["digest"] == d1 and "build" not in spec, "the IaC repo pins the image's digest, with no build")
    approve(app)
    h1 = iac_head(iac)["sha"]
    dispatch(app=app, branch="main", sha=h1, action="deploy", actor="cicd-e2e")
    meta, rt = deployed(app, "dev", h1, iac)
    check(meta["image"].endswith("@" + d1), "dev runs the same digest")
    check(rt == "success", "cicd/runtime: running")
    code, sbom = api("GET", f"/repos/{STATE}/raw/envs/{CLUSTER}/{app}/dev/evidence/sbom.cdx.json")
    n = len((sbom if isinstance(sbom, dict) else {}).get("components") or [])
    check(code == 200 and n > 10, f"an SBOM of the prebuilt image is kept ({n} components)")
    d2 = push_image("docker.io/nginxinc/nginx-unprivileged:1.28-alpine", "stable")
    check(d2 != d1, "the tag now points at another image")
    h2 = wait("the bot to follow the tag", lambda: (lambda c: c if c and f"Image-Digest: {d2}" in c["commit"]["message"] else None)(
        iac_head(iac)), timeout=900, every=20)
    meta, rt = deployed(app, "dev", h2["sha"], iac)
    check(meta["image"].endswith("@" + d2) and rt == "success", "dev runs the new digest")


def nested(slot, *args, check=True):
    """kubectl in a nested cluster, through its node (the stack runner's credentials: exec in the slot)."""
    env = dict(os.environ, KUBECONFIG=os.environ.get("STACK_KUBECONFIG", ""))
    r = subprocess.run(["kubectl", "-n", slot, "exec", "node", "--", *args], capture_output=True, text=True, env=env)
    if check and r.returncode != 0:
        raise Fail(f"nested {' '.join(args[:4])}: {r.stderr.strip()[-200:]}")
    return r.stdout


@scenario
def v8_target():
    """fx-target (direct): dev on c-local; prod on the target c-nested (a kept stack in stack-slot-2), served there."""
    import fixtures
    app, repo, target, slot = "fxt", fixtures.ensure_repo("fx-target"), "c-nested", "stack-slot-2"
    nested(slot, "true")
    check(True, f"the target {target}'s node is up in {slot}")
    unenroll(app)
    files = overlay_files("t1", "- op: replace\n  path: /spec/template/spec/containers/0/resources/requests/memory\n  value: 48Mi\n", app=app)
    cfg = yaml.safe_load(files["cicd.yaml"])
    cfg["spec"]["environments"]["prod"]["cluster"] = target
    files["cicd.yaml"] = yaml.safe_dump(cfg, sort_keys=False)
    enroll_record(app, {"repo": repo, "clusters": [CLUSTER, target]})
    fixtures.hook(repo)
    s1 = fixtures.write_tree(repo, files, "fixture: target", reset=True)
    dispatch(app=app, branch="main", sha=s1, action="deploy", actor="cicd-e2e")
    meta, rt = deployed(app, "dev", s1, repo)
    check(rt == "success", "dev runs on c-local")
    dispatch(app=app, branch="main", sha=s1, action="request-promotion", actor="cicd-e2e")
    pr = wait("the promotion PR", lambda: next((p for p in api("GET", f"/repos/{STATE}/pulls?state=open&limit=20")[1] or []
                                               if p["head"]["ref"].startswith(f"promote/{app}-prod-")), None), timeout=600)
    code, _ = api("POST", f"/repos/{STATE}/pulls/{pr['number']}/merge", {"Do": "merge", "MergeTitleField": pr["title"]})
    check(code in (200, 204), f"merged promotion PR #{pr['number']}")
    path = f"envs/{target}/{app}/prod/cicd-env.yaml"
    meta = wait(f"{path}", lambda: (lambda c: yaml.safe_load(c) if isinstance(c, str) else None)(
        api("GET", f"/repos/{STATE}/raw/{path}")[1]), timeout=900, every=20)
    check(meta.get("commit") == s1 and meta.get("builtOn") == CLUSTER, f"prod is rendered for {target}, built on {CLUSTER}")
    check("@sha256:" in meta["image"] and meta["image"].startswith("localhost:5000/"), "the same digest, pulled through the slot's mirror")
    wait(f"{app} to be Available on {target}", lambda: "True" in nested(slot, "k0s", "kubectl", "-n", app, "get", "deploy", app, "-o",
         "jsonpath={.status.conditions[?(@.type=='Available')].status}", check=False) or
         nested(slot, "k0s", "kubectl", "-n", app, "get", "httpscaledobject", "-o", "name", check=False).strip(), timeout=900, every=20)
    ip = nested(slot, "k0s", "kubectl", "-n", "keda", "get", "svc", "keda-add-ons-http-interceptor-proxy", "-o", "jsonpath={.spec.clusterIP}")
    host = meta["hosts"][0]
    body = wait(f"{host} through {target}'s interceptor", lambda: (lambda o: o if "t1" in o else None)(
        nested(slot, "wget", "-q", "-T", "30", "-O-", "--header", f"Host: {host}", f"http://{ip}:8080/", check=False)), timeout=600, every=15)
    check("t1" in body, f"{app} answers on {target} (woken from zero by its interceptor)")
    unenroll(app)


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
