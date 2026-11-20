#!/usr/bin/env python3
"""runtime: after a deploy, watch the environment and say what happened, in one word and a hint.

  runtime.py watch --root . --cluster c-local --app NAME --env-dir DIR --sha SHA \\
                   [--kubeconfig FILE] [--out runtime.json] [--github-output]
  runtime.py statuses runtime.json --repo owner/name --sha SHA [--server URL] [--target-url URL]

`watch` waits for Flux to apply this build (the workload's pod template names its digest), sends
one request to the environment's host through the gateway (which also wakes a scaled-to-zero
app), and watches this build's pods for about 90 s. Then it classifies what it saw with the
`runtime` table in contract.yaml: running, image-pull, crash, oom, rejected, config,
unschedulable, not-ready, localhost, unreachable, http-error, not-started, not-applied.
runtime.json keeps what the class was decided from (pod states, events, the last log lines).

It reads the cluster as the platform's runtime ServiceAccount (platform/runtime): pods, events,
logs and workloads in environment namespaces only. --kubeconfig (or $RUNTIME_KUBECONFIG) is a
kubeconfig with a token; without one, `watch` says the check isn't configured and exits 0.

`statuses` posts the result as the commit status cicd/runtime on the app repo (FORGEJO_TOKEN).

Needs Python 3.10+ and PyYAML.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import re
import ssl
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
import external  # noqa: E402  (probe(): HTTPS to a host through the gateway)
import intake    # noqa: E402  (contract())

STATE = {"ok": "success", "warn": "warning", "fail": "failure"}
PULL = {"ErrImagePull", "ImagePullBackOff", "InvalidImageName", "ErrImageNeverPull"}
CONFIG = {"CreateContainerConfigError", "CreateContainerError", "RunContainerError"}
LOCALHOST = re.compile(r"\b(127\.0\.0\.1|localhost|\[::1\]):\d+")


def classes() -> dict[str, dict]:
    return {c["id"]: c for c in intake.contract()["runtime"]}


# ---------------------------------------------------------------- classification (no I/O)


def _statuses(pod: dict) -> list[dict]:
    st = pod.get("status") or {}
    return (st.get("initContainerStatuses") or []) + (st.get("containerStatuses") or [])


def _ready(pod: dict) -> bool:
    return any(c.get("type") == "Ready" and c.get("status") == "True" for c in (pod.get("status") or {}).get("conditions") or [])


def _probe_failures(events: list[dict]) -> list[str]:
    return [e.get("message", "") for e in events if e.get("reason") == "Unhealthy" and "Readiness" in e.get("message", "")]


def classify(obs: dict, final: bool) -> dict | None:
    """What the observations say, or None if it's too early to tell (only when not final).

    obs: applied (bool), pods (this build's pods), events (about them and their ReplicaSets),
    http ({status, error} or None while the request is out), logs ({container: text}),
    scale_to_zero (bool), elapsed (s since applied)."""
    def out(cid: str, detail: str = "", **kw) -> dict:
        return {"class": cid, "detail": detail, **kw}

    if not obs["applied"]:
        return out("not-applied") if final else None
    events, pods = obs["events"], obs["pods"]

    for e in events:  # the ReplicaSet couldn't create a pod: admission said no
        if e.get("reason") == "FailedCreate":
            m = e.get("message", "")
            hit = re.search(r"violates PodSecurity \"restricted[^\"]*\": (.*)", m)
            return out("rejected", hit.group(1) if hit else m[:200])

    for p in pods:
        for c in _statuses(p):
            w = (c.get("state") or {}).get("waiting") or {}
            if w.get("reason") in PULL:
                return out("image-pull", f"{c['name']}: {w.get('message', w['reason'])[:200]}", container=c["name"])
            if w.get("reason") in CONFIG:
                return out("config", f"{c['name']}: {w.get('message', w['reason'])[:200]}", container=c["name"])
    for p in pods:
        for c in _statuses(p):
            t = (c.get("state") or {}).get("terminated") or (c.get("lastState") or {}).get("terminated") or {}
            if t.get("reason") == "OOMKilled":
                return out("oom", f"{c['name']}: killed at its memory limit", container=c["name"], pod=p["metadata"]["name"])
    for p in pods:
        for c in _statuses(p):
            w = (c.get("state") or {}).get("waiting") or {}
            t = (c.get("state") or {}).get("terminated") or (c.get("lastState") or {}).get("terminated")
            if t and not _ready(p) and (w.get("reason") == "CrashLoopBackOff" or c.get("restartCount", 0) >= 2 or final):
                code = t.get("exitCode")
                return out("crash", f"{c['name']}: exits {code}" + (" (finished: nothing kept running)" if code == 0 else ""),
                           container=c["name"], pod=p["metadata"]["name"], exit_code=code)

    unsched = [e.get("message", "") for e in events if e.get("reason") == "FailedScheduling"]
    if unsched and not any(_ready(p) for p in pods) and (final or obs["elapsed"] > 30):
        return out("unschedulable", unsched[-1][:200])

    ready = [p for p in pods if _ready(p)]
    h = obs.get("http")
    if ready:
        if h is None:
            return None if not final else out("running", "ready (no answer from the host yet)")
        if h.get("error"):
            return out("unreachable", h["error"][:200]) if final else None
        if h["status"] >= 500:
            return out("http-error", f"{h['status']} from {obs.get('host', 'the host')}") if final else None
        return out("running", f"answers {h['status']}")

    if not final:
        return None
    if not pods:
        why = "" if not obs.get("scale_to_zero") else ("the request to the host didn't wake it"
                                                         + (f" ({h['error'][:120]})" if h and h.get("error") else ""))
        return out("not-started", why)
    probes = _probe_failures(events)
    last = probes[-1][:200] if probes else "readiness never passed"
    logs = "\n".join((obs.get("logs") or {}).values())
    if probes and "connection refused" in probes[-1] and LOCALHOST.search(logs):
        return out("localhost", f"{LOCALHOST.search(logs).group(0)} in the log; {last}")
    return out("not-ready", last)


def verdict(found: dict) -> dict:
    c = classes()[found["class"]]
    return {**found, "keyword": c["keyword"], "state": c["state"], "rule": c.get("rule"), "hint": c["hint"]}


def summary(v: dict) -> str:
    d = f" ({v['detail']})" if v.get("detail") and v["state"] != "ok" else f": {v['detail']}" if v.get("detail") else ""
    return f"{v['keyword']}{d}" + (f". {v['hint']}" if v["state"] != "ok" else "")


# ---------------------------------------------------------------- the cluster


class Kube:
    def __init__(self, kubeconfig: Path):
        kc = yaml.safe_load(kubeconfig.read_text())
        ctx_name = kc.get("current-context")
        ctx = next((c["context"] for c in kc.get("contexts") or [] if c["name"] == ctx_name), None)
        cl = next(c["cluster"] for c in kc["clusters"] if ctx is None or c["name"] == ctx["cluster"])
        us = next(u["user"] for u in kc["users"] if ctx is None or u["name"] == ctx["user"])
        self.server = cl["server"].rstrip("/")
        self.token = us["token"]
        self.ctx = ssl.create_default_context()
        if cl.get("certificate-authority-data"):
            self.ctx.load_verify_locations(cadata=base64.b64decode(cl["certificate-authority-data"]).decode())
        elif cl.get("insecure-skip-tls-verify"):
            self.ctx.check_hostname, self.ctx.verify_mode = False, ssl.CERT_NONE

    def _get(self, path: str, params: dict | None = None) -> tuple[int, bytes]:
        url = self.server + path + ("?" + urllib.parse.urlencode(params) if params else "")
        req = urllib.request.Request(url, headers={"Authorization": f"Bearer {self.token}"})
        try:
            with urllib.request.urlopen(req, timeout=20, context=self.ctx) as r:
                return r.status, r.read()
        except urllib.error.HTTPError as e:
            return e.code, e.read()

    def get(self, path: str, params: dict | None = None) -> dict | None:
        code, body = self._get(path, params)
        if code == 404:
            return None
        if code != 200:
            raise RuntimeError(f"GET {path}: {code} {body[:200]!r}")
        return json.loads(body)

    def log(self, ns: str, pod: str, container: str, previous: bool) -> str:
        code, body = self._get(f"/api/v1/namespaces/{ns}/pods/{pod}/log",
                               {"container": container, "tailLines": 20, "previous": str(previous).lower()})
        return body.decode(errors="replace") if code == 200 else ""


class Request:
    """One request to the environment's host at a time, in the background (a cold start holds it)."""

    def __init__(self, host: str, via: str | None, timeout: float):
        self.host, self.via, self.timeout = host, via, timeout
        self.result: dict | None = None
        self.started = 0.0
        self.thread: threading.Thread | None = None

    def start(self):
        self.result, self.started = None, time.monotonic()

        def go():
            try:
                status, _ = external.probe(self.host, "/", self.via, timeout=self.timeout)
                self.result = {"status": status}
            except Exception as e:  # noqa: BLE001: any failure to get an answer is the finding
                self.result = {"error": f"{type(e).__name__}: {e}"}
        self.thread = threading.Thread(target=go, daemon=True)
        self.thread.start()

    def busy(self) -> bool:
        return self.thread is not None and self.thread.is_alive()


def this_build(objs: list[dict], digest: str) -> list[dict]:
    return [o for o in objs if digest in json.dumps(((o.get("spec") or {}).get("template") or {}).get("spec") or o.get("spec") or {})]


def observe(k: Kube, ns: str, workload: dict, digest: str, host: str | None, via: str | None, stz: dict,
            wait_applied: float, window: float, say=print) -> tuple[dict, dict]:
    kind = workload.get("kind", "Deployment").lower() + "s"
    t0 = time.monotonic()
    say(f"waiting for {workload['name']} in {ns} to run {digest[:19]}... (Flux applies it)")
    while True:
        w = k.get(f"/apis/apps/v1/namespaces/{ns}/{kind}/{workload['name']}")
        if w and this_build([w], digest):
            break
        if time.monotonic() - t0 > wait_applied:
            obs = {"applied": False, "pods": [], "events": [], "http": None, "logs": {}, "elapsed": 0}
            return obs, classify(obs, final=True)
        time.sleep(5)
    say(f"applied after {time.monotonic() - t0:.0f} s; watching for up to {window:.0f} s")

    cold = float(str(stz.get("coldStartTimeout", "60s")).rstrip("s") or 60) if stz.get("enabled") else 20
    req = Request(host, via, cold + 15) if host else None
    if req:
        req.start()
    t1 = time.monotonic()
    ready_since = None
    while True:
        elapsed = time.monotonic() - t1
        final = elapsed >= window
        pods = this_build((k.get(f"/api/v1/namespaces/{ns}/pods") or {}).get("items", []), digest)
        rss = this_build((k.get(f"/apis/apps/v1/namespaces/{ns}/replicasets") or {}).get("items", []), digest)
        mine = {p["metadata"]["name"] for p in pods} | {r["metadata"]["name"] for r in rss}
        events = sorted((e for e in (k.get(f"/api/v1/namespaces/{ns}/events") or {}).get("items", [])
                         if (e.get("involvedObject") or {}).get("name") in mine),
                        key=lambda e: e.get("lastTimestamp") or e.get("eventTime") or "")
        if any(_ready(p) for p in pods) and ready_since is None:
            ready_since = time.monotonic()
        # a request that failed before the pod was ready says nothing about the ready pod: ask again
        if req and not req.busy() and ready_since and req.result and (req.result.get("error") or req.result.get("status", 0) >= 500) \
                and req.started < ready_since:
            req.start()
        obs = {"applied": True, "pods": pods, "events": events, "http": None if (not req or req.busy()) else req.result,
               "host": host, "logs": {}, "scale_to_zero": bool(stz.get("enabled")), "elapsed": elapsed}
        if req is None:
            obs["http"] = {"status": 0}
        if final:
            obs["logs"] = logs_of(k, ns, pods, previous=False)   # they decide not-ready vs localhost
        found = classify(obs, final)
        if found:
            if found["class"] in ("crash", "oom"):   # the run that died, not the restart
                obs["logs"] = logs_of(k, ns, [p for p in pods if p["metadata"]["name"] == found.get("pod")] or pods, previous=True)
            elif not obs["logs"] and found["class"] not in ("running", "not-applied"):
                obs["logs"] = logs_of(k, ns, pods, previous=False)
            return obs, found
        time.sleep(3)


def logs_of(k: Kube, ns: str, pods: list[dict], previous: bool) -> dict[str, str]:
    out = {}
    for p in pods[:2]:
        for c in _statuses(p):
            text = k.log(ns, p["metadata"]["name"], c["name"], previous) or (k.log(ns, p["metadata"]["name"], c["name"], False) if previous else "")
            if text:
                out[f"{p['metadata']['name']}/{c['name']}"] = text
    return out


def slim(obs: dict) -> dict:
    """What to keep as evidence: states, not whole objects."""
    return {
        "applied": obs["applied"], "http": obs.get("http"), "logs": obs.get("logs") or {},
        "pods": [{"name": p["metadata"]["name"], "phase": (p.get("status") or {}).get("phase"), "ready": _ready(p),
                  "containers": [{k: c.get(k) for k in ("name", "ready", "restartCount", "state", "lastState")} for c in _statuses(p)]}
                 for p in obs.get("pods", [])],
        "events": [{k: e.get(k) for k in ("type", "reason", "message", "count", "lastTimestamp")} | {"object": (e.get("involvedObject") or {}).get("name")}
                   for e in obs.get("events", [])][-30:],
    }


# ---------------------------------------------------------------- cli


def post_status(v: dict, server: str, repo: str, sha: str, target: str, token: str) -> int:
    body = json.dumps({"context": "cicd/runtime", "state": STATE[v["state"]], "description": summary(v)[:250],
                       "target_url": target}).encode()
    req = urllib.request.Request(f"{server.rstrip('/')}/api/v1/repos/{repo}/statuses/{sha}", data=body, method="POST",
                                 headers={"Authorization": f"token {token}", "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    w = sub.add_parser("watch")
    w.add_argument("--root", default=".", help="the platform repo checkout (envs/, clusters/)")
    w.add_argument("--cluster", required=True)
    w.add_argument("--app", required=True)
    w.add_argument("--env-dir", required=True)
    w.add_argument("--sha", required=True, help="the commit this run deployed")
    w.add_argument("--kubeconfig", default=os.environ.get("RUNTIME_KUBECONFIG", ""))
    w.add_argument("--wait-applied", type=float, default=300)
    w.add_argument("--window", type=float, default=90)
    w.add_argument("--out", default="runtime.json")
    w.add_argument("--github-output", action="store_true")
    st = sub.add_parser("statuses")
    st.add_argument("runtime_json")
    st.add_argument("--repo", required=True)
    st.add_argument("--sha", required=True)
    st.add_argument("--server", default=os.environ.get("FORGEJO_URL", "https://forge.goblincorps.com"))
    st.add_argument("--target-url", default="")
    a = ap.parse_args()

    if a.cmd == "statuses":
        r = json.loads(Path(a.runtime_json).read_text())
        token = os.environ.get("FORGEJO_TOKEN", "")
        if r.get("state") not in STATE:
            return
        code = post_status(r, a.server, a.repo, a.sha, a.target_url, token) if token else 0
        if code not in (200, 201):
            print(f"::notice::runtime status not posted on {a.repo} ({code or 'no token'})")
        return

    def output(**kv):
        if a.github_output and os.environ.get("GITHUB_OUTPUT"):
            with open(os.environ["GITHUB_OUTPUT"], "a") as f:
                f.writelines(f"{k}={v}\n" for k, v in kv.items())

    root = Path(a.root)
    env_dir = root / "envs" / a.cluster / a.app / a.env_dir
    meta = yaml.safe_load((env_dir / "cicd-env.yaml").read_text())
    if meta.get("commit") != a.sha:
        print(f"::notice::{a.app}/{a.env_dir} now runs {str(meta.get('commit'))[:7]}, a later deploy: its own run checks it")
        Path(a.out).write_text(json.dumps({"state": "superseded"}))
        output(state="superseded")
        return
    if not a.kubeconfig:
        print("::notice::runtime check not configured (no CICD_RUNTIME_KUBECONFIG secret): see docs/enroll.md")
        Path(a.out).write_text(json.dumps({"state": "unconfigured"}))
        output(state="unconfigured")
        return
    kc = Path(a.kubeconfig)
    if not kc.exists():  # the secret itself, not a path
        fd, name = tempfile.mkstemp(suffix=".kubeconfig")
        os.write(fd, a.kubeconfig.encode()); os.close(fd)
        kc = Path(name)
    app = yaml.safe_load((env_dir / "cicd.yaml").read_text())["spec"]
    cl = yaml.safe_load((root / "clusters" / a.cluster / "cicd-cluster.yaml").read_text())
    digest = meta["image"].partition("@")[2]
    host = (meta.get("hosts") or [None])[0]
    stz = app.get("scaleToZero") or {}
    window = max(a.window, float(str(stz.get("coldStartTimeout", "60s")).rstrip("s") or 60) + 30) if stz.get("enabled") else a.window

    obs, found = observe(Kube(kc), meta["namespace"], app["workload"], digest, host, (cl.get("probe") or {}).get("via"),
                         stz, a.wait_applied, window)
    v = verdict(found)
    rec = {"schema": "runtime/v1", "app": a.app, "env": a.env_dir, "commit": a.sha, "image": meta["image"], "host": host,
           **{k: v[k] for k in ("class", "keyword", "state", "rule", "hint", "detail")}, "summary": summary(v),
           "observed": slim(obs)}
    Path(a.out).write_text(json.dumps(rec, indent=1))
    output(state=v["state"], keyword=v["keyword"])
    print(f"runtime: {summary(v)}")
    for name, text in (obs.get("logs") or {}).items():
        print(f"\n--- last lines of {name} ---\n{text.rstrip()}")
    if v["state"] == "fail":
        print(f"::error::{summary(v)}")
    elif v["state"] == "warn":
        print(f"::warning::{summary(v)}")


if __name__ == "__main__":
    main()
