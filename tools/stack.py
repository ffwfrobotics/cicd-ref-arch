#!/usr/bin/env python3
"""stack: a cluster as a pipeline job (docs/stacks.md), provider k0s-pod: one privileged pod in a slot
namespace of the host cluster (platform/stacks), reached only through kubectl exec.

  KUBECONFIG=<cicd-stack/runner> tools/stack.py lifecycle --name stack-ref --run 912 \
      --repo ffwf-iac/stack-ref --sha <commit> --path cluster --out stack.json [--keep]

lifecycle = up, bootstrap, check, down (down always, unless --keep). Each step's result and timing goes
to --out (JSON), the evidence the pipeline keeps. The steps can be run one at a time as well.

- up: a free slot (no node pod in it), the node pod from images/stack-node, k0s's config with the
  nested cluster's own CIDRs; waits for the nested node to be Ready.
- bootstrap: Flux in the nested cluster (flux install --export), a GitRepository on the stack's IaC
  repo at the commit (submodules included: the stack pins what it runs), a Kustomization at --path.
  The forge credentials are the bot's, put into the nested cluster only, which is gone after down.
- check: every Flux Kustomization Ready within --timeout; the word is ready, not-ready <names>, or timeout.
- down: the node pod and its config.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

SLOTS = ("stack-slot-1", "stack-slot-2")
NODE_IMAGE = os.environ.get("STACK_NODE_IMAGE", "localhost:5000/stack-node:v1.37.2-k0s.1")
K0S_CONFIG = """apiVersion: k0s.k0sproject.io/v1beta1
kind: ClusterConfig
metadata: {name: stack}
spec:
  network:
    provider: kuberouter
    podCIDR: 10.250.0.0/16        # the host cluster uses k0s's default 10.244.0.0/16 (docs/stacks.md)
    serviceCIDR: 10.251.0.0/16
  telemetry: {enabled: false}
"""


def kubectl(*args, input=None, check=True, timeout=300) -> str:
    r = subprocess.run(["kubectl", *args], input=input, capture_output=True, text=True, timeout=timeout)
    if check and r.returncode != 0:
        raise RuntimeError(f"kubectl {' '.join(args[:4])}: {r.stderr.strip()[-400:]}")
    return r.stdout


def nested(slot: str, *args, input=None, check=True, timeout=300) -> str:
    """kubectl in the nested cluster, through exec into its node."""
    return kubectl("-n", slot, "exec", *(["-i"] if input is not None else []), "node", "--",
                   "k0s", "kubectl", *args, input=input, check=check, timeout=timeout)


def node_manifests(name: str, run: str) -> str:
    labels = {"app.kubernetes.io/name": "stack-node", "cicd.ffwf.net/stack": name, "cicd.ffwf.net/run": str(run)}
    cm = {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "node-config", "labels": labels},
          "data": {"k0s.yaml": K0S_CONFIG}}
    pod = {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": "node", "labels": labels},
           "spec": {"hostname": f"{name}-{run}"[:63], "enableServiceLinks": False, "automountServiceAccountToken": False,
                    "containers": [{
                        "name": "k0s", "image": NODE_IMAGE, "imagePullPolicy": "IfNotPresent",
                        "args": ["k0s", "controller", "--config=/etc/stack/k0s.yaml", "--enable-worker", "--no-taints",
                                 "--kubelet-extra-args=--eviction-hard=imagefs.available<1Gi,nodefs.available<1Gi,memory.available<100Mi"],
                        "securityContext": {"privileged": True},
                        "resources": {"requests": {"cpu": "500m", "memory": "1Gi"}, "limits": {"memory": "6Gi"}},
                        "volumeMounts": [{"name": "config", "mountPath": "/etc/stack"},
                                         {"name": "k0s", "mountPath": "/var/lib/k0s"},
                                         {"name": "modules", "mountPath": "/lib/modules", "readOnly": True}]}],
                    "volumes": [{"name": "config", "configMap": {"name": "node-config"}},
                                {"name": "k0s", "emptyDir": {}},
                                {"name": "modules", "hostPath": {"path": "/lib/modules"}}]}}
    return json.dumps({"apiVersion": "v1", "kind": "List", "items": [cm, pod]})


def free_slot() -> str:
    for s in SLOTS:
        if not kubectl("-n", s, "get", "pod", "node", "--ignore-not-found", "-o", "name").strip():
            return s
    raise RuntimeError("no free stack slot: both are in use (one lifecycle each; try again when one is down)")


def wait(what, fn, timeout, every=5):
    t0 = time.time()
    while time.time() - t0 < timeout:
        try:
            v = fn()
        except (RuntimeError, subprocess.TimeoutExpired):
            v = None
        if v:
            return v, time.time() - t0
        time.sleep(every)
    raise TimeoutError(f"{what} not within {timeout}s")


def up(a, rec) -> str:
    slot = a.slot or free_slot()
    kubectl("-n", slot, "apply", "-f", "-", input=node_manifests(a.name, a.run))
    rec["slot"] = slot
    _, t = wait("the node pod Ready", lambda: "true" in kubectl("-n", slot, "get", "pod", "node", "-o",
                                                                "jsonpath={.status.containerStatuses[0].ready}"), 300)
    _, t2 = wait("the nested node Ready", lambda: " Ready" in nested(slot, "get", "nodes", "--no-headers", timeout=30), 300)
    rec["steps"]["up"] = {"result": "ok", "seconds": round(t + t2), "image": NODE_IMAGE}
    print(f"up: {slot}, nested node Ready in {t + t2:.0f}s")
    return slot


def bootstrap(a, rec, slot):
    t0 = time.time()
    flux = subprocess.run(["flux", "install", "--export", "--components", "source-controller,kustomize-controller,helm-controller"],
                          capture_output=True, text=True, check=True).stdout
    nested(slot, "apply", "--server-side", "-f", "-", input=flux, timeout=600)
    wait("Flux controllers", lambda: nested(slot, "-n", "flux-system", "get", "deploy", "-o",
                                            "jsonpath={range .items[*]}{.status.readyReplicas}{' '}{end}", timeout=30).split().count("1") >= 3, 600)
    user, token = os.environ.get("BOT", "cicd-bot"), os.environ["FORGEJO_TOKEN"]
    secret = {"apiVersion": "v1", "kind": "Secret", "metadata": {"name": "forge", "namespace": "flux-system"},
              "stringData": {"username": user, "password": token}}
    src = {"apiVersion": "source.toolkit.fluxcd.io/v1", "kind": "GitRepository",
           "metadata": {"name": "stack", "namespace": "flux-system"},
           "spec": {"interval": "10m", "url": f"{a.server.rstrip('/')}/{a.repo}.git", "ref": {"commit": a.sha},
                    "recurseSubmodules": True, "secretRef": {"name": "forge"}}}
    ks = {"apiVersion": "kustomize.toolkit.fluxcd.io/v1", "kind": "Kustomization",
          "metadata": {"name": "stack", "namespace": "flux-system"},
          "spec": {"interval": "10m", "retryInterval": "20s", "path": f"./{a.path.strip('./')}", "prune": True,
                   "sourceRef": {"kind": "GitRepository", "name": "stack"}}}
    nested(slot, "apply", "-f", "-", input=json.dumps({"apiVersion": "v1", "kind": "List", "items": [secret, src, ks]}))
    rec["steps"]["bootstrap"] = {"result": "ok", "seconds": round(time.time() - t0), "repo": a.repo, "commit": a.sha, "path": a.path}
    print(f"bootstrap: Flux at {a.repo}@{a.sha[:7]} ./{a.path}")


def kustomizations(slot) -> list[dict]:
    out = json.loads(nested(slot, "get", "kustomizations.kustomize.toolkit.fluxcd.io", "-A", "-o", "json", timeout=60))
    res = []
    for k in out.get("items", []):
        ready = next((c for c in (k.get("status") or {}).get("conditions") or [] if c["type"] == "Ready"), {})
        res.append({"name": k["metadata"]["name"], "ready": ready.get("status") == "True",
                    "reason": ready.get("reason"), "message": (ready.get("message") or "")[:200]})
    return res


def check(a, rec, slot) -> str:
    t0 = time.time()
    ks = []
    while time.time() - t0 < a.timeout:
        try:
            ks = kustomizations(slot)
        except (RuntimeError, subprocess.TimeoutExpired, json.JSONDecodeError):
            ks = []
        # the root Kustomization creates the others: ready when it is, and everything it made is
        if ks and all(k["ready"] for k in ks) and len(ks) >= a.min_kustomizations:
            break
        time.sleep(10)
    secs = round(time.time() - t0)
    bad = [k["name"] for k in ks if not k["ready"]]
    word = "ready" if ks and not bad and len(ks) >= a.min_kustomizations else ("timeout" if not ks else f"not-ready {' '.join(bad) or '(too few)'}")
    rec["steps"]["check"] = {"result": word, "seconds": secs, "kustomizations": ks}
    print(f"check: {word} after {secs}s ({len(ks)} Kustomizations)")
    return word


def down(a, rec, slot):
    kubectl("-n", slot, "delete", "pod", "node", "--ignore-not-found", "--grace-period=5", "--wait=true", timeout=180, check=False)
    kubectl("-n", slot, "delete", "configmap", "node-config", "--ignore-not-found", check=False)
    rec["steps"]["down"] = {"result": "ok"}
    print(f"down: {slot} is free")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("step", choices=["lifecycle", "up", "bootstrap", "check", "down"])
    ap.add_argument("--name", required=True)
    ap.add_argument("--run", default=str(int(time.time())))
    ap.add_argument("--slot", help="default: a free one (up), or required for the single steps after it")
    ap.add_argument("--repo", help="the stack's IaC repo, owner/name")
    ap.add_argument("--sha", help="its commit")
    ap.add_argument("--path", default="cluster", help="the Flux tree in the IaC repo")
    ap.add_argument("--server", default=os.environ.get("FORGEJO_URL", "https://forge.goblincorps.com"))
    ap.add_argument("--timeout", type=int, default=900)
    ap.add_argument("--min-kustomizations", type=int, default=2, help="the root and at least one it makes")
    ap.add_argument("--out", default="stack.json")
    ap.add_argument("--keep", action="store_true", help="lifecycle: leave the cluster up (debugging)")
    a = ap.parse_args()
    rec = {"stack": a.name, "run": a.run, "provider": "k0s-pod", "steps": {}}
    slot = a.slot
    rc = 0
    try:
        if a.step in ("lifecycle", "up"):
            slot = up(a, rec)
        if a.step in ("lifecycle", "bootstrap"):
            bootstrap(a, rec, slot)
        if a.step in ("lifecycle", "check"):
            rc = 0 if check(a, rec, slot) == "ready" else 1
    except (RuntimeError, TimeoutError, subprocess.CalledProcessError) as e:
        rec["error"] = str(e)[-500:]
        print(f"error: {rec['error']}", file=sys.stderr)
        rc = 2
    finally:
        if slot and (a.step == "down" or (a.step == "lifecycle" and not a.keep)):
            down(a, rec, slot)
        Path(a.out).write_text(json.dumps(rec, indent=2) + "\n")
    rec["word"] = (rec["steps"].get("check") or {}).get("result") or ("error" if rc == 2 else "ok")
    Path(a.out).write_text(json.dumps(rec, indent=2) + "\n")
    print(f"result: {rec['word']}")
    return rc


if __name__ == "__main__":
    sys.exit(main())
