#!/usr/bin/env python3
"""stack: a cluster as a pipeline job (docs/stacks.md), behind a provider contract (akb #493).

  KUBECONFIG=<cicd-stack/runner> tools/stack.py lifecycle --name stack-ref --run 912 --cluster c-local \
      --repo ffwf-iac/stack-ref --sha <commit> --path cluster [--provider k0s-pod] [--out stack.json] [--keep]

The platform owns the slots (clusters/<cluster>/stack-slots.yaml: names, address ranges, API port).
A provider makes a cluster in a slot and returns a ClusterHandle; everything after `up` (Flux
bootstrap, checks, evidence) uses only the handle's kubeconfig. Providers:

  k0s-pod   one privileged k0s pod in the slot namespace (images/stack-node); isolation none;
            capabilities api, nodes, cni. Threat model: the node is privileged in the host cluster;
            its private cgroup namespace keeps the nested kubelet away from the host's pods (it
            once tried to "clean up" c-local's kubepods without it).
  vcluster  a virtual control plane as unprivileged pods in the slot (platform/stacks/providers,
            pinned); its workloads run on the host's nodes. Capabilities: api only.

lifecycle = up, bootstrap, check, down (down always, unless --keep). Evidence goes to --out (JSON).
From a workstation, --port-forward reaches the nested API through kubectl port-forward.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Literal, Protocol

import yaml

ROOT = Path(__file__).resolve().parent.parent
Isolation = Literal["none", "userns", "vm"]


# ---------------------------------------------------------------- the contract


@dataclass(frozen=True)
class Slot:                 # allocated by the platform, never the provider
    name: str
    pod_cidr: str
    svc_cidr: str
    api_port: int
    dns_name: str
    mirrors: tuple = ()     # ((host, endpoint), ...): image names this cluster resolves to the host's registry


@dataclass(frozen=True)
class ClusterRequest:
    slot: Slot
    name: str               # the stack
    run: str
    fleet_ref: str          # <repo>@<commit>:<path>, what bootstrap points Flux at
    k0s_config: str = ""    # the stack's cluster/k0s/config.yaml, if any: merged under the slot's settings
    registry: str = ""      # where the cluster pulls images from (a mirror); empty: the internet
    secrets_ref: str = ""   # per-stack secrets (SOPS/age), none yet
    data_ref: str | None = None
    ttl_s: int | None = None


@dataclass(frozen=True)
class ClusterHandle:
    kubeconfig: str
    api_endpoint: str
    registry: str
    capabilities: frozenset[str]
    isolation: Isolation
    provider: str           # name@version


class Provider(Protocol):
    name: str
    version: str
    capabilities: frozenset[str]
    isolation: Isolation
    needs_host: bool

    def up(self, req: ClusterRequest) -> ClusterHandle: ...    # idempotent per slot
    def ready(self, h: ClusterHandle) -> dict: ...             # evidence
    def down(self, slot: Slot) -> None: ...                    # idempotent, safe after a failed up


def load_slots(root: Path, cluster: str) -> list[Slot]:
    d = yaml.safe_load((root / "clusters" / cluster / "stack-slots.yaml").read_text())
    mirrors = tuple((m["host"], m["endpoint"]) for m in d.get("registryMirrors") or [])
    return [Slot(s["name"], s["podCIDR"], s["serviceCIDR"], int(s.get("apiPort", 6443)), f"api.{s['name']}.svc.cluster.local", mirrors)
            for s in d["slots"]]


# ---------------------------------------------------------------- helpers


def kubectl(*args, kubeconfig: str | None = None, input=None, check=True, timeout=300) -> str:
    cmd = ["kubectl", *(["--kubeconfig", kubeconfig] if kubeconfig else []), *args]
    r = subprocess.run(cmd, input=input, capture_output=True, text=True, timeout=timeout)
    if check and r.returncode != 0:
        raise RuntimeError(f"kubectl {' '.join(args[:4])}: {r.stderr.strip()[-400:]}")
    return r.stdout


def wait(what, fn, timeout, every=5):
    t0 = time.time()
    while time.time() - t0 < timeout:
        try:
            v = fn()
        except (RuntimeError, subprocess.TimeoutExpired, json.JSONDecodeError):
            v = None
        if v:
            return v, time.time() - t0
        time.sleep(every)
    raise TimeoutError(f"{what} not within {timeout}s")


class HandleFile:
    """The handle's kubeconfig as a file, for kubectl."""
    def __init__(self, h: ClusterHandle):
        fd, self.path = tempfile.mkstemp(prefix="stack-kc-")
        os.write(fd, h.kubeconfig.encode())
        os.close(fd)

    def __call__(self, *args, **kw):
        return kubectl(*args, kubeconfig=self.path, **kw)


# ---------------------------------------------------------------- provider k0s-pod


class K0sPod:
    name = "k0s-pod"
    version = "1"
    capabilities = frozenset({"api", "nodes", "cni"})
    isolation: Isolation = "none"
    needs_host = False
    image = os.environ.get("STACK_NODE_IMAGE", "localhost:5000/stack-node:v1.37.2-k0s.1")

    def __init__(self, port_forward: bool = False):
        self.port_forward = port_forward
        self._pf = None

    def k0s_config(self, s: Slot, stack_config: str = "") -> str:
        """The stack's own k0s settings, with the slot's ranges and API names on top: the platform allocates those."""
        cfg = yaml.safe_load(stack_config) if stack_config else None
        cfg = cfg or {"apiVersion": "k0s.k0sproject.io/v1beta1", "kind": "ClusterConfig", "metadata": {"name": "stack"}, "spec": {}}
        spec = cfg.setdefault("spec", {})
        spec.setdefault("telemetry", {"enabled": False})
        api = spec.setdefault("api", {})
        api["sans"] = sorted(set(api.get("sans") or []) | {s.dns_name, f"api.{s.name}", "127.0.0.1", "localhost"})
        net = spec.setdefault("network", {})
        net.setdefault("provider", "kuberouter")
        net["podCIDR"], net["serviceCIDR"] = s.pod_cidr, s.svc_cidr
        return yaml.safe_dump(cfg)

    def manifests(self, req: ClusterRequest) -> str:
        s = req.slot
        labels = {"app.kubernetes.io/name": "stack-node", "cicd.ffwf.net/stack": req.name, "cicd.ffwf.net/run": str(req.run)}
        data = {"k0s.yaml": self.k0s_config(s, req.k0s_config)}
        if s.mirrors:     # containerd (config v3) reads hosts.toml per registry from config_path
            data["containerd-mirrors.toml"] = ('version = 3\n[plugins."io.containerd.cri.v1.images".registry]\n'
                                               '  config_path = "/etc/k0s/certs.d"\n')
            for i, (host, endpoint) in enumerate(s.mirrors):
                data[f"hosts-{i}.toml"] = (f'server = "{endpoint}"\n[host."{endpoint}"]\n'
                                           '  capabilities = ["pull", "resolve"]\n  skip_verify = true\n')
        cm = {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "node-config", "labels": labels}, "data": data}
        # k0s writes into /etc/k0s, so the drop-ins are copied there at start rather than mounted
        setup = "mkdir -p /etc/k0s/containerd.d && "
        if s.mirrors:
            setup += "cp /etc/stack/containerd-mirrors.toml /etc/k0s/containerd.d/ && "
            for i, (host, _) in enumerate(s.mirrors):
                setup += f"mkdir -p '/etc/k0s/certs.d/{host}' && cp /etc/stack/hosts-{i}.toml '/etc/k0s/certs.d/{host}/hosts.toml' && "
        svc = {"apiVersion": "v1", "kind": "Service", "metadata": {"name": "api", "labels": labels},
               "spec": {"selector": {"app.kubernetes.io/name": "stack-node"},
                        "ports": [{"name": "api", "port": s.api_port, "targetPort": 6443}]}}
        pod = {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": "node", "labels": labels},
               "spec": {"hostname": f"{req.name}-{req.run}"[:63], "enableServiceLinks": False, "automountServiceAccountToken": False,
                        "containers": [{
                            "name": "k0s", "image": self.image, "imagePullPolicy": "IfNotPresent",
                            "command": ["/bin/sh", "-c", setup + 'exec /usr/local/bin/stack-node-entry "$@"', "sh"],
                            "args": ["k0s", "controller", "--config=/etc/stack/k0s.yaml", "--enable-worker", "--no-taints",
                                     "--kubelet-extra-args=--eviction-hard=imagefs.available<1Gi,nodefs.available<1Gi,memory.available<100Mi"],
                            "ports": [{"name": "api", "containerPort": 6443}],
                            "securityContext": {"privileged": True},
                            "resources": {"requests": {"cpu": "500m", "memory": "1Gi"}, "limits": {"memory": "6Gi"}},
                            "volumeMounts": [{"name": "config", "mountPath": "/etc/stack"},
                                             {"name": "k0s", "mountPath": "/var/lib/k0s"},
                                             {"name": "modules", "mountPath": "/lib/modules", "readOnly": True}]}],
                        "volumes": [{"name": "config", "configMap": {"name": "node-config"}},
                                    {"name": "k0s", "emptyDir": {}},
                                    {"name": "modules", "hostPath": {"path": "/lib/modules"}}]}}
        return json.dumps({"apiVersion": "v1", "kind": "List", "items": [cm, svc, pod]})

    def up(self, req: ClusterRequest) -> ClusterHandle:
        s = req.slot
        kubectl("-n", s.name, "apply", "-f", "-", input=self.manifests(req))
        wait("the node pod Ready", lambda: "true" in kubectl("-n", s.name, "get", "pod", "node", "-o",
                                                             "jsonpath={.status.containerStatuses[0].ready}"), 300)
        wait("the nested API", lambda: " Ready" in kubectl("-n", s.name, "exec", "node", "--", "k0s", "kubectl", "get", "nodes",
                                                           "--no-headers", timeout=30), 300)
        kc = yaml.safe_load(kubectl("-n", s.name, "exec", "node", "--", "k0s", "kubeconfig", "admin"))
        endpoint = f"https://{s.dns_name}:{s.api_port}"
        if self.port_forward:
            endpoint = f"https://127.0.0.1:{self._forward(s)}"
        for c in kc["clusters"]:
            c["cluster"]["server"] = endpoint
        return ClusterHandle(kubeconfig=yaml.safe_dump(kc), api_endpoint=endpoint, registry=req.registry,
                             capabilities=self.capabilities, isolation=self.isolation, provider=f"{self.name}@{self.version}")

    def _forward(self, s: Slot) -> int:
        with socket.socket() as so:
            so.bind(("127.0.0.1", 0))
            port = so.getsockname()[1]
        self._pf = subprocess.Popen(["kubectl", "-n", s.name, "port-forward", "svc/api", f"{port}:{s.api_port}"],
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(2)
        return port

    def ready(self, h: ClusterHandle) -> dict:
        k = HandleFile(h)
        nodes = json.loads(k("get", "nodes", "-o", "json", timeout=30))["items"]
        ok = [n for n in nodes if any(c["type"] == "Ready" and c["status"] == "True" for c in n["status"]["conditions"])]
        return {"nodes": len(nodes), "ready": len(ok), "version": nodes[0]["status"]["nodeInfo"]["kubeletVersion"] if nodes else None}

    def down(self, slot: Slot) -> None:
        if self._pf:
            self._pf.terminate()
        for kind in ("pod/node", "service/api", "configmap/node-config"):
            kubectl("-n", slot.name, "delete", kind, "--ignore-not-found", "--grace-period=5", "--wait=true", timeout=180, check=False)


# ---------------------------------------------------------------- provider vcluster


class VCluster:
    """A virtual control plane (vcluster) as ordinary pods in the slot; its workloads are synced onto the host's
    nodes. Not privileged. Capabilities: api only (no nodes, CNI or CSI of its own), so checks that need them are
    recorded as not exercised here. The manifests are pinned in platform/stacks/providers."""
    name = "vcluster"
    version = "0.38.0"
    capabilities = frozenset({"api"})
    isolation: Isolation = "none"
    needs_host = False

    def __init__(self, port_forward: bool = False):
        self.port_forward = port_forward
        self._pf = None
        self.template = ROOT / "platform" / "stacks" / "providers" / f"vcluster-{self.version}.yaml"

    def manifests(self, req: ClusterRequest) -> str:
        """The pinned template for this slot (SLOTNS replaced), with the config Secret made from its plain file: no
        Secret manifest is kept in git."""
        docs = [d for d in yaml.safe_load_all(self.template.read_text().replace("SLOTNS", req.slot.name)) if d]
        cfg = self.template.with_name(f"vcluster-{self.version}-config.yaml").read_text().replace("SLOTNS", req.slot.name)
        docs.append({"apiVersion": "v1", "kind": "Secret", "type": "Opaque",
                     "metadata": {"name": "vc-config-vc", "namespace": req.slot.name, "labels": {"app": "vcluster", "release": "vc"}},
                     "stringData": {"config.yaml": cfg}})
        return json.dumps({"apiVersion": "v1", "kind": "List", "items": docs})

    def up(self, req: ClusterRequest) -> ClusterHandle:
        s = req.slot
        kubectl("-n", s.name, "apply", "-f", "-", input=self.manifests(req))
        wait("the vcluster control plane", lambda: kubectl("-n", s.name, "get", "deploy", "vc", "-o",
                                                           "jsonpath={.status.readyReplicas}").strip() == "1", 600)
        raw = wait("its kubeconfig", lambda: kubectl("-n", s.name, "get", "secret", "vc-vc", "-o", "jsonpath={.data.config}").strip(), 300)[0]
        kc = yaml.safe_load(__import__("base64").b64decode(raw))
        endpoint = f"https://vc.{s.name}.svc.cluster.local:443"
        if self.port_forward:
            with socket.socket() as so:
                so.bind(("127.0.0.1", 0))
                port = so.getsockname()[1]
            self._pf = subprocess.Popen(["kubectl", "-n", s.name, "port-forward", "svc/vc", f"{port}:443"],
                                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(2)
            endpoint = f"https://127.0.0.1:{port}"
        for c in kc["clusters"]:
            c["cluster"]["server"] = endpoint
        return ClusterHandle(kubeconfig=yaml.safe_dump(kc), api_endpoint=endpoint, registry=req.registry,
                             capabilities=self.capabilities, isolation=self.isolation, provider=f"{self.name}@{self.version}")

    def ready(self, h: ClusterHandle) -> dict:
        k = HandleFile(h)
        v = json.loads(k("version", "-o", "json", timeout=30)).get("serverVersion") or {}
        return {"version": v.get("gitVersion")}

    def down(self, slot: Slot) -> None:
        if self._pf:
            self._pf.terminate()
        kubectl("-n", slot.name, "delete", "-f", "-", "--ignore-not-found", "--wait=true", timeout=300, check=False,
                input=self.manifests(ClusterRequest(slot=slot, name="", run="", fleet_ref="")))
        # what it synced onto the host
        kubectl("-n", slot.name, "delete", "pods,services,configmaps,secrets,endpoints,serviceaccounts", "-l",
                "vcluster.loft.sh/managed-by=vc", "--ignore-not-found", "--wait=true", timeout=300, check=False)


PROVIDERS = {"k0s-pod": K0sPod, "vcluster": VCluster}


# ---------------------------------------------------------------- after up: only the handle


def pinned_submodules(server: str, repo: str, sha: str, token: str) -> dict[str, dict]:
    """name -> {path, repo, commit} for a commit's top-level submodules on this forge."""
    def get(path):
        req = urllib.request.Request(f"{server.rstrip('/')}/api/v1/repos/{repo}/{path}", headers={"Authorization": f"token {token}"})
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.read()
    tree = json.loads(get(f"git/trees/{sha}")).get("tree") or []
    links = {x["path"]: x["sha"] for x in tree if x.get("type") == "commit"}
    if not links:
        return {}
    urls, cur = {}, None
    for line in get(f"raw/.gitmodules?ref={sha}").decode().splitlines():
        line = line.strip()
        if line.startswith("path"):
            cur = line.split("=", 1)[1].strip()
        elif line.startswith("url") and cur:
            urls[cur] = line.split("=", 1)[1].strip()
    out = {}
    for path, commit in links.items():
        u = urls.get(path, "")
        full = (os.path.normpath(os.path.join("/" + repo, u)) if u.startswith(".") else "/" + "/".join(u.split("://", 1)[-1].split("/")[1:]))
        full = full[:-4] if full.endswith(".git") else full
        out[re.sub(r"[^a-z0-9-]+", "-", path.lower()).strip("-")[:63]] = {
            "path": path, "repo": "/".join(full.strip("/").split("/")[-2:]), "commit": commit}
    return out


def anonymous_ok(server: str, repo: str) -> bool:
    """Can anyone clone it? (A repo shown as public in a private org can't be: try, don't read flags.)"""
    try:
        with urllib.request.urlopen(f"{server.rstrip('/')}/{repo}.git/info/refs?service=git-upload-pack", timeout=30) as r:
            return r.status == 200
    except urllib.error.HTTPError:
        return False


FORGE_SSH = os.environ.get("FORGE_SSH", "ssh://git@forge.goblincorps.com:42222")


def deploy_key(a, secret_name: str, repo: str, token: str) -> tuple[dict, dict]:
    """A read-only deploy key for one repo and one run: (the Secret for Flux, {repo, id} to delete at down).
    The key is made with openssl (an ed25519 PKCS#8 key, which Flux's SSH library reads); the forge's host key
    comes from the platform's config: CI runners can't reach the forge's SSH port to scan it."""
    import base64
    import struct
    pem = subprocess.run(["openssl", "genpkey", "-algorithm", "ed25519"], capture_output=True, text=True, check=True).stdout
    der = subprocess.run(["openssl", "pkey", "-pubout", "-outform", "DER"], input=pem.encode(), capture_output=True, check=True).stdout
    wire = lambda b: struct.pack(">I", len(b)) + b                                  # noqa: E731
    pub = "ssh-ed25519 " + base64.b64encode(wire(b"ssh-ed25519") + wire(der[-32:])).decode()
    if not a.known_hosts:
        raise RuntimeError("no forgeKnownHosts in the slots config: a deploy key can't be used without the forge's host key")
    sec = {"apiVersion": "v1", "kind": "Secret", "metadata": {"name": secret_name, "namespace": "flux-system"},
           "stringData": {"identity": pem, "identity.pub": pub, "known_hosts": a.known_hosts}}
    body = json.dumps({"title": f"stack {a.name} run {a.run}", "key": pub, "read_only": True}).encode()
    req = urllib.request.Request(f"{a.server.rstrip('/')}/api/v1/repos/{repo}/keys", data=body, method="POST",
                                 headers={"Authorization": f"token {token}", "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=30) as r:
        key_id = json.loads(r.read())["id"]
    return sec, {"repo": repo, "id": key_id}


def drop_keys(a, keys: list[dict]):
    token = os.environ.get("FORGEJO_TOKEN", "")
    for k in keys:
        req = urllib.request.Request(f"{a.server.rstrip('/')}/api/v1/repos/{k['repo']}/keys/{k['id']}", method="DELETE",
                                     headers={"Authorization": f"token {token}"})
        try:
            urllib.request.urlopen(req, timeout=30)
        except urllib.error.HTTPError:
            pass


def bootstrap(h: ClusterHandle, a) -> dict:
    """Flux in the cluster, at the stack's IaC repo commit and each submodule it pins (one GitRepository each:
    Flux's recurseSubmodules can't check out a submodule of a specific commit)."""
    k = HandleFile(h)
    flux = subprocess.run(["flux", "install", "--export", "--components", "source-controller,kustomize-controller,helm-controller"],
                          capture_output=True, text=True, check=True).stdout
    k("apply", "--server-side", "-f", "-", input=flux, timeout=600)
    wait("Flux controllers", lambda: k("-n", "flux-system", "get", "deploy", "-o",
                                       "jsonpath={range .items[*]}{.status.readyReplicas}{' '}{end}", timeout=30).split().count("1") >= 3, 600)
    token = os.environ["FORGEJO_TOKEN"]
    server = a.server.rstrip("/")
    subs = pinned_submodules(a.server, a.repo, a.sha, token)
    # No platform credentials go into a stack's cluster: whoever writes the stack repo decides what Flux applies
    # there (as cluster-admin), so they could read them. A repo anyone can clone needs none; any other gets a
    # deploy key of its own for this run: read-only, that repo only, deleted at down.
    secrets = []

    def git(name, repo, commit):
        spec = {"interval": "10m", "url": f"{server}/{repo}.git", "ref": {"commit": commit}}
        if not anonymous_ok(a.server, repo):
            sec, key = deploy_key(a, f"key-{name}", repo, token)
            secrets.append(sec)
            a.deploy_keys.append(key)
            spec.update(url=f"{FORGE_SSH}/{repo}.git", secretRef={"name": f"key-{name}"})
        return {"apiVersion": "source.toolkit.fluxcd.io/v1", "kind": "GitRepository",
                "metadata": {"name": name, "namespace": "flux-system"}, "spec": spec}
    sources = [git("stack", a.repo, a.sha), *[git(n, x["repo"], x["commit"]) for n, x in subs.items()]]
    items = [*secrets, *sources,
             {"apiVersion": "kustomize.toolkit.fluxcd.io/v1", "kind": "Kustomization", "metadata": {"name": "stack", "namespace": "flux-system"},
              "spec": {"interval": "10m", "retryInterval": "20s", "path": f"./{a.path.strip('./')}", "prune": True,
                       "sourceRef": {"kind": "GitRepository", "name": "stack"}}}]
    if a.serve_target:   # a kept stack as a deploy target (docs/stacks.md "Targets"): its Flux also follows envs/<target>/
        items += [{"apiVersion": "source.toolkit.fluxcd.io/v1", "kind": "GitRepository", "metadata": {"name": "platform-envs", "namespace": "flux-system"},
                   "spec": {"interval": "1m", "url": f"{server}/{a.platform_repo}.git", "ref": {"branch": "master"},
                            "ignore": f"/*\n!/envs/{a.serve_target}/\n"}},
                  {"apiVersion": "kustomize.toolkit.fluxcd.io/v1", "kind": "Kustomization", "metadata": {"name": "envs", "namespace": "flux-system"},
                   "spec": {"interval": "1m", "retryInterval": "20s", "path": f"./envs/{a.serve_target}", "prune": True,
                            "dependsOn": [{"name": "stack"}], "sourceRef": {"kind": "GitRepository", "name": "platform-envs"}}}]
        if not anonymous_ok(a.server, a.platform_repo):
            raise RuntimeError(f"{a.platform_repo} can't be read anonymously: a target needs a per-target deploy key (not built)")
    k("apply", "-f", "-", input=json.dumps({"apiVersion": "v1", "kind": "List", "items": items}))
    return {"repo": a.repo, "commit": a.sha, "path": a.path, "sources": [{"name": n, **x} for n, x in subs.items()],
            "deploy_keys": [k["repo"] for k in a.deploy_keys]}


def repo_file(a, path: str) -> str:
    """A file of the stack's IaC repo at the commit being run ("" if it isn't there)."""
    req = urllib.request.Request(f"{a.server.rstrip('/')}/api/v1/repos/{a.repo}/raw/{path}?ref={a.sha}",
                                 headers={"Authorization": f"token {os.environ['FORGEJO_TOKEN']}"})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.read().decode()
    except urllib.error.HTTPError:
        return ""


def kustomizations(k) -> list[dict]:
    out = []
    for x in json.loads(k("get", "kustomizations.kustomize.toolkit.fluxcd.io", "-A", "-o", "json", timeout=60)).get("items", []):
        ready = next((c for c in (x.get("status") or {}).get("conditions") or [] if c["type"] == "Ready"), {})
        out.append({"name": x["metadata"]["name"], "ready": ready.get("status") == "True",
                    "reason": ready.get("reason"), "message": (ready.get("message") or "")[:200]})
    return out


KUBECTL_IMAGE = os.environ.get("STACK_KUBECTL_IMAGE", "cgr.dev/chainguard/kubectl:latest-dev@sha256:ee975dba7273819f032fec5e7b2ccf27189b1389f0d0930a5a9c98a8d8e3dd80")  # has a shell for the script


def smoke(h: ClusterHandle, script: str, needs: list[str], timeout: int = 300) -> dict:
    """The stack's own check script, run INSIDE the nested cluster as a Job with that cluster's kubectl: never on
    the platform's runner, where it would sit next to the platform's credentials (akb #493, correction 1)."""
    missing = sorted(set(needs) - set(h.capabilities))
    if missing:
        return {"result": "not-exercised", "needs": sorted(needs), "not_exercised": missing}
    k = HandleFile(h)
    ns = "stack-checks"
    items = [{"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": ns}},
             {"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {"name": "smoke", "namespace": ns}},
             {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRoleBinding", "metadata": {"name": "stack-smoke"},
              "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": "view"},
              "subjects": [{"kind": "ServiceAccount", "name": "smoke", "namespace": ns}]},
             # view has no cluster-scoped kinds: the CRDs, nodes, classes and API services a platform check reads. Never Secrets.
             {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRole", "metadata": {"name": "stack-smoke-cluster"},
              "rules": [{"apiGroups": ["apiextensions.k8s.io"], "resources": ["customresourcedefinitions"], "verbs": ["get", "list"]},
                        {"apiGroups": [""], "resources": ["nodes", "namespaces"], "verbs": ["get", "list"]},
                        {"apiGroups": ["networking.k8s.io"], "resources": ["ingressclasses"], "verbs": ["get", "list"]},
                        {"apiGroups": ["gateway.networking.k8s.io"], "resources": ["*"], "verbs": ["get", "list"]},
                        {"apiGroups": ["apiregistration.k8s.io"], "resources": ["apiservices"], "verbs": ["get", "list"]}]},
             {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRoleBinding", "metadata": {"name": "stack-smoke-cluster"},
              "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": "stack-smoke-cluster"},
              "subjects": [{"kind": "ServiceAccount", "name": "smoke", "namespace": ns}]},
             {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "smoke", "namespace": ns}, "data": {"smoke.sh": script}},
             {"apiVersion": "batch/v1", "kind": "Job", "metadata": {"name": "smoke", "namespace": ns},
              "spec": {"backoffLimit": 0, "activeDeadlineSeconds": timeout, "template": {"spec": {
                  "serviceAccountName": "smoke", "restartPolicy": "Never",
                  "containers": [{"name": "smoke", "image": KUBECTL_IMAGE, "command": ["/usr/bin/sh", "/check/smoke.sh"],
                                  "volumeMounts": [{"name": "check", "mountPath": "/check"}]}],
                  "volumes": [{"name": "check", "configMap": {"name": "smoke", "defaultMode": 0o555}}]}}}}]
    k("apply", "-f", "-", input=json.dumps({"apiVersion": "v1", "kind": "List", "items": items}))
    t0 = time.time()
    state = ""
    while time.time() - t0 < timeout + 30:
        st = json.loads(k("-n", ns, "get", "job", "smoke", "-o", "json", timeout=30)).get("status") or {}
        if st.get("succeeded"):
            state = "passed"
            break
        if st.get("failed"):
            state = "failed"
            break
        time.sleep(5)
    logs = k("-n", ns, "logs", "job/smoke", "--tail=20", check=False, timeout=30)
    return {"result": state or "timeout", "seconds": round(time.time() - t0), "needs": sorted(needs),
            "exercised": sorted(needs), "log": logs[-1500:]}


def check(h: ClusterHandle, a) -> dict:
    """Every Flux Kustomization Ready (at least --min-kustomizations of them) within --timeout. A check names the
    capabilities it needs (--needs); one the provider lacks is recorded as not exercised, never as passed."""
    k = HandleFile(h)
    needs = set(a.needs or [])
    t0, ks = time.time(), []
    while time.time() - t0 < a.timeout:
        try:
            ks = kustomizations(k)
        except (RuntimeError, subprocess.TimeoutExpired, json.JSONDecodeError):
            ks = []
        if ks and all(x["ready"] for x in ks) and len(ks) >= a.min_kustomizations:
            break
        time.sleep(10)
    bad = [x["name"] for x in ks if not x["ready"]]
    word = ("ready" if ks and not bad and len(ks) >= a.min_kustomizations
            else "timeout" if not ks else f"not-ready {' '.join(bad) or '(too few)'}")
    return {"result": word, "seconds": round(time.time() - t0), "kustomizations": ks,
            "needs": sorted(needs), "exercised": sorted(needs & set(h.capabilities)),
            "not_exercised": sorted(needs - set(h.capabilities))}


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("step", choices=["lifecycle", "down"])
    ap.add_argument("--name", required=True)
    ap.add_argument("--run", default=str(int(time.time())))
    ap.add_argument("--cluster", default=os.environ.get("CLUSTER", "c-local"), help="the host cluster (its stack-slots.yaml)")
    ap.add_argument("--provider", default="k0s-pod", choices=sorted(PROVIDERS))
    ap.add_argument("--slot", help="a slot name (default: the first free one)")
    ap.add_argument("--repo", help="the stack's IaC repo, owner/name")
    ap.add_argument("--sha", help="its commit")
    ap.add_argument("--path", default="cluster", help="the Flux tree in the IaC repo (without --definition)")
    ap.add_argument("--definition", help="the stack's definition dir: base/, k0s/config.yaml, providers/<provider>/")
    ap.add_argument("--server", default=os.environ.get("FORGEJO_URL", "https://forge.goblincorps.com"))
    ap.add_argument("--timeout", type=int, default=900)
    ap.add_argument("--min-kustomizations", type=int, default=2)
    ap.add_argument("--needs", nargs="*", default=[], help="capabilities the stack's checks need")
    ap.add_argument("--serve-target", help="keep it up as this deploy target: its Flux follows envs/<target>/ of the platform repo")
    ap.add_argument("--platform-repo", default=os.environ.get("STATE_REPO", "ffwf/cicd-ref-arch"))
    ap.add_argument("--smoke", help="the stack's check script (a path in its repo), run inside the nested cluster")
    ap.add_argument("--smoke-needs", nargs="*", default=["api"])
    ap.add_argument("--root", default=str(ROOT), help="the platform repo (clusters/<cluster>/stack-slots.yaml)")
    ap.add_argument("--port-forward", action="store_true", help="reach the nested API through kubectl port-forward (a workstation)")
    ap.add_argument("--out", default="stack.json")
    ap.add_argument("--keep", action="store_true", help="leave the cluster up (debugging)")
    a = ap.parse_args()
    a.deploy_keys = []
    slots = {s.name: s for s in load_slots(Path(a.root), a.cluster)}
    a.known_hosts = (yaml.safe_load((Path(a.root) / "clusters" / a.cluster / "stack-slots.yaml").read_text()) or {}).get("forgeKnownHosts", "")
    prov = PROVIDERS[a.provider](port_forward=a.port_forward)
    rec = {"stack": a.name, "run": a.run, "provider": f"{prov.name}@{prov.version}", "isolation": prov.isolation,
           "capabilities": sorted(prov.capabilities), "steps": {}}
    if a.step == "down":
        prov.down(slots[a.slot])
        print(f"down: {a.slot} is free")
        return 0

    def free() -> Slot:
        for s in slots.values():
            if not kubectl("-n", s.name, "get", "pod", "node", "--ignore-not-found", "-o", "name").strip():
                return s
        raise RuntimeError("no free stack slot: all are in use")

    slot, rc = None, 0
    try:
        slot = slots[a.slot] if a.slot else free()
        rec["slot"] = asdict(slot)
        t0 = time.time()
        k0s_cfg = repo_file(a, f"{a.definition}/k0s/config.yaml") if a.definition else ""
        if a.definition and repo_file(a, f"{a.definition}/providers/{prov.name}/kustomization.yaml"):
            a.path = f"{a.definition}/providers/{prov.name}"       # the provider's overlay of the stack's base
        h = prov.up(ClusterRequest(slot=slot, name=a.name, run=a.run, fleet_ref=f"{a.repo}@{a.sha}:{a.path}", k0s_config=k0s_cfg))
        rec["steps"]["up"] = {"result": "ok", "seconds": round(time.time() - t0), "api": h.api_endpoint, **prov.ready(h)}
        print(f"up: {slot.name}, {h.provider}, nested API {h.api_endpoint} in {rec['steps']['up']['seconds']}s")
        t0 = time.time()
        rec["steps"]["bootstrap"] = {"result": "ok", **bootstrap(h, a), "seconds": round(time.time() - t0)}
        print(f"bootstrap: Flux at {a.repo}@{a.sha[:7]} ./{a.path}, {len(rec['steps']['bootstrap']['sources'])} pinned source(s)")
        c = rec["steps"]["check"] = check(h, a)
        print(f"check: {c['result']} after {c['seconds']}s ({len(c['kustomizations'])} Kustomizations)"
              + (f"; not exercised here: {', '.join(c['not_exercised'])}" if c["not_exercised"] else ""))
        rc = 0 if c["result"] == "ready" else 1
        if rc == 0 and a.smoke:
            sm = rec["steps"]["smoke"] = smoke(h, repo_file(a, a.smoke), a.smoke_needs)
            print(f"smoke: {sm['result']}" + (f" ({sm.get('seconds')}s)" if sm.get("seconds") is not None else ""))
            rc = 0 if sm["result"] in ("passed", "not-exercised") else 1
    except (RuntimeError, TimeoutError, subprocess.CalledProcessError, KeyError) as e:
        rec["error"] = str(e)[-500:]
        print(f"error: {rec['error']}", file=sys.stderr)
        rc = 2
    finally:
        if slot and not a.keep:
            prov.down(slot)
            drop_keys(a, a.deploy_keys)
            rec["steps"]["down"] = {"result": "ok", "deploy_keys_removed": len(a.deploy_keys)}
            print(f"down: {slot.name} is free" + (f", {len(a.deploy_keys)} deploy key(s) removed" if a.deploy_keys else ""))
    word = (rec["steps"].get("check") or {}).get("result") or ("error" if rc == 2 else "ok")
    if word == "ready" and (rec["steps"].get("smoke") or {}).get("result") in ("failed", "timeout"):
        word = f"smoke-{rec['steps']['smoke']['result']}"
    rec["word"] = word
    Path(a.out).write_text(json.dumps(rec, indent=2) + "\n")
    print(f"result: {rec['word']}")
    return rc


if __name__ == "__main__":
    sys.exit(main())
