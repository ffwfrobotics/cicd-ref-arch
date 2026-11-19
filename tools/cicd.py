#!/usr/bin/env python3
"""cicd: render environments and handle promotions for cicd-ref-arch.

CI calls this. It also runs on a laptop to preview exactly what CI would write.

Subcommands:
  hosts             print the hostnames an environment gets
  render            write envs/<cluster>/<app>/<env>/ from an app's cicd.yaml, a built deploy base and an image digest
  index             regenerate envs/<cluster>/kustomization.yaml from the env directories present
  request-promotion write promotions/pending/<id>/ pinned to what the source environment runs now
  apply-due         apply pending promotions whose notBefore has passed and whose PR was approved
  gc                remove branch environments whose branch no longer exists

Needs Python 3.10+ and PyYAML (actions/setup installs it).
"""
from __future__ import annotations

import argparse
import datetime as dt
import fnmatch
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import urllib.request
from pathlib import Path

import yaml

API = "cicd.ffwf.net/v1alpha1"
RESERVED_ENVS = {"dev", "prod"}
LABEL_MAX = 63

# ---------------------------------------------------------------- config


def load_yaml(path: Path):
    with open(path) as f:
        return yaml.safe_load(f)


def dump_yaml(obj) -> str:
    return yaml.safe_dump(obj, sort_keys=False, default_flow_style=False)


def write(path: Path, text: str):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


def load_app(path: str) -> dict:
    app = load_yaml(Path(path))
    if app.get("apiVersion") != API or app.get("kind") != "App":
        sys.exit(f"{path}: expected apiVersion {API}, kind App")
    spec = app.setdefault("spec", {})
    name = app["metadata"]["name"]
    if not re.fullmatch(r"[a-z]([a-z0-9-]{0,30}[a-z0-9])?", name):
        sys.exit(f"{path}: app name {name!r} must be a DNS label of at most 32 characters")
    envs = spec.setdefault("environments", {})
    envs.setdefault("dev", {}).setdefault("host", "{app}-dev.{cluster}.{zone}")
    envs["dev"].setdefault("branch", "master")
    envs.setdefault("branch", {}).setdefault("host", "{app}-{branch}.{cluster}.{zone}")
    envs["branch"].setdefault("exclude", ["promote/*"])
    envs.setdefault("prod", {}).setdefault("host", "{app}.{cluster}.{zone}")
    stz = spec.setdefault("scaleToZero", {})
    stz.setdefault("enabled", True)
    stz.setdefault("idleSeconds", 900)
    stz.setdefault("coldStartTimeout", "60s")
    stz.setdefault("maxReplicas", 3)
    stz.setdefault("targetConcurrency", 50)
    spec.setdefault("service", {"name": name, "port": 80})
    spec.setdefault("workload", {"kind": "Deployment", "name": name})
    spec.setdefault("egress", [])
    return app


def load_cluster(root: Path, cluster: str) -> dict:
    path = root / "clusters" / cluster / "cicd-cluster.yaml"
    if not path.exists():
        sys.exit(f"no cluster config at {path}")
    return load_yaml(path)


# ---------------------------------------------------------------- names


def slug(text: str, budget: int) -> str:
    """A DNS-label-safe slug of at most `budget` characters, stable for long inputs."""
    s = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-") or "x"
    if len(s) > budget:
        h = hashlib.sha1(text.encode()).hexdigest()[:6]
        s = s[: budget - 7].rstrip("-") + "-" + h
    return s


def branch_slug(app: str, branch: str) -> str:
    # <app>-<slug> has to fit in one DNS label (and is the namespace name)
    s = slug(branch, LABEL_MAX - len(app) - 1)
    if s in RESERVED_ENVS:
        s = s + "-br"
    return s


def env_id(app: dict, env: str, branch: str | None) -> tuple[str, str]:
    """(directory name, namespace) for an environment."""
    name = app["metadata"]["name"]
    if env == "prod":
        return "prod", name
    if env == "dev":
        return "dev", f"{name}-dev"
    if env == "branch":
        if not branch:
            sys.exit("--branch is required for the branch environment")
        s = branch_slug(name, branch)
        return f"branch-{s}", f"{name}-{s}"
    sys.exit(f"unknown environment {env!r}: dev, branch or prod")


def hosts_for(app: dict, env: str, branch: str | None, cluster: str, zone: str) -> list[str]:
    name = app["metadata"]["name"]
    spec = app["spec"]["environments"][env]
    vals = {"app": name, "cluster": cluster, "zone": zone,
            "branch": branch_slug(name, branch) if branch else ""}
    hosts = [spec["host"].format(**vals)]
    hosts += [h.format(**vals) for h in spec.get("extraHosts", [])]
    for h in hosts:
        for label in h.split("."):
            if not re.fullmatch(r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?", label):
                sys.exit(f"host {h!r}: label {label!r} is not a valid DNS label")
    return hosts


def branch_wanted(app: dict, branch: str) -> bool:
    envs = app["spec"]["environments"]
    if branch == envs["dev"]["branch"]:
        return False
    return not any(fnmatch.fnmatch(branch, p) for p in envs["branch"].get("exclude", []))


# ---------------------------------------------------------------- render


def platform_objects(app: dict, cl: dict, ns: str, hosts: list[str], zone_hosts: list[str]) -> list[dict]:
    spec = app["spec"]
    name = app["metadata"]["name"]
    svc = spec["service"]
    stz = spec["scaleToZero"]
    keda = cl["keda"]
    gw = cl["gateway"]
    objs = []

    # default deny; traffic in only from the path that serves it (interceptor or gateway)
    ingress_from = (
        [{"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": keda["namespace"]}}}]
        if stz["enabled"] else
        [{"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": gw["namespace"]}}}]
    )
    egress = [{
        "to": [{"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "kube-system"}},
                "podSelector": {"matchLabels": {"k8s-app": "kube-dns"}}}],
        "ports": [{"protocol": "UDP", "port": 53}, {"protocol": "TCP", "port": 53}],
    }]
    for rule in spec["egress"]:  # app-declared egress, e.g. {cidr: 0.0.0.0/0, ports: [443]}
        egress.append({"to": [{"ipBlock": {"cidr": rule["cidr"], "except": rule.get("except", [])}}],
                       "ports": [{"protocol": "TCP", "port": p} for p in rule.get("ports", [443])]})
    objs.append({"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
                 "metadata": {"name": "default"},
                 "spec": {"podSelector": {}, "policyTypes": ["Ingress", "Egress"],
                          "ingress": [{"from": ingress_from}], "egress": egress}})

    if stz["enabled"]:
        # Hosts under the cluster zone reach the interceptor through the platform's wildcard
        # route; the interceptor picks this route by Host header and holds requests while a
        # pod starts.
        objs.append({
            "apiVersion": "http.keda.sh/v1beta1", "kind": "InterceptorRoute",
            "metadata": {"name": name},
            "spec": {
                "target": {"service": svc["name"], "port": svc["port"]},
                "rules": [{"hosts": hosts}],
                "scalingMetric": {"concurrency": {"targetValue": stz["targetConcurrency"]}},
                "timeouts": {"readiness": stz["coldStartTimeout"]},
            }})
        objs.append({
            "apiVersion": "keda.sh/v1alpha1", "kind": "ScaledObject",
            "metadata": {"name": name},
            "spec": {
                "scaleTargetRef": {"kind": spec["workload"]["kind"], "name": spec["workload"]["name"]},
                "minReplicaCount": 0,
                "maxReplicaCount": stz["maxReplicas"],
                "cooldownPeriod": stz["idleSeconds"],
                "triggers": [{"type": "external-push", "metadata": {
                    "scalerAddress": keda["scaler"], "interceptorRoute": name}}],
            }})
    else:
        objs.append({
            "apiVersion": "gateway.networking.k8s.io/v1", "kind": "HTTPRoute",
            "metadata": {"name": name},
            "spec": {"parentRefs": [{"name": gw["name"], "namespace": gw["namespace"],
                                     "sectionName": gw.get("httpsListener", "https")}],
                     "hostnames": hosts,
                     "rules": [{"backendRefs": [{"name": svc["name"], "port": svc["port"]}]}]}})
    return objs


def edge_objects(app: dict, cl: dict, ns: str, env_dir: str, extra: list[str]) -> list[dict]:
    """Hosts outside the cluster zone (custom domains) need their own route to the interceptor."""
    if not extra or not app["spec"]["scaleToZero"]["enabled"]:
        return []
    keda, gw = cl["keda"], cl["gateway"]
    name = f"{app['metadata']['name']}-{env_dir}"
    return [{
        "apiVersion": "gateway.networking.k8s.io/v1", "kind": "HTTPRoute",
        "metadata": {"name": name, "namespace": keda["namespace"],
                     "labels": {"cicd.ffwf.net/app": app["metadata"]["name"], "cicd.ffwf.net/env": env_dir}},
        "spec": {"parentRefs": [{"name": gw["name"], "namespace": gw["namespace"],
                                 "sectionName": gw.get("customListener", "custom-https")}],
                 "hostnames": extra,
                 "rules": [{"backendRefs": [{"name": keda["interceptor"]["service"],
                                             "port": keda["interceptor"]["port"]}]}]}}]


def render_env(root: Path, app: dict, cl: dict, env: str, branch: str | None, image: str,
               app_manifests: str, meta: dict, app_config_text: str | None = None) -> Path:
    name = app["metadata"]["name"]
    zone, cluster = cl["zone"], cl["cluster"]
    env_dir, ns = env_id(app, env, branch)
    hosts = hosts_for(app, env, branch, cluster, zone)
    zone_hosts = [h for h in hosts if h.endswith("." + zone)]
    extra = [h for h in hosts if not h.endswith("." + zone)]
    out = root / "envs" / cluster / name / env_dir
    if out.exists():
        shutil.rmtree(out)
    labels = {"cicd.ffwf.net/app": name, "cicd.ffwf.net/env": env_dir}

    repo, _, digest = image.partition("@")
    if not digest.startswith("sha256:"):
        sys.exit(f"image {image!r} must be pinned by digest (<repo>@sha256:...)")

    write(out / "namespace.yaml", dump_yaml({
        "apiVersion": "v1", "kind": "Namespace",
        "metadata": {"name": ns, "labels": {
            **labels,
            "pod-security.kubernetes.io/enforce": "restricted",
            "pod-security.kubernetes.io/warn": "restricted"}}}))
    write(out / "app.yaml", app_manifests)
    # the app's cicd.yaml as it was for this build: promotions render prod from it, so an app in
    # another repo can be promoted without this repo knowing where that repo is
    write(out / "cicd.yaml", app_config_text if app_config_text is not None else dump_yaml(app))
    write(out / "platform.yaml", "---\n".join(dump_yaml(o) for o in platform_objects(app, cl, ns, hosts, zone_hosts)))
    write(out / "kustomization.yaml", dump_yaml({
        "apiVersion": "kustomize.config.k8s.io/v1beta1", "kind": "Kustomization",
        "namespace": ns,
        "labels": [{"pairs": labels, "includeSelectors": False}],
        "resources": ["namespace.yaml", "app.yaml", "platform.yaml"],  # not cicd*.yaml: data, not objects
        "images": [{"name": "app-image", "newName": repo, "digest": digest}],
    }))
    edge = edge_objects(app, cl, ns, env_dir, extra)
    if edge:
        write(out / "edge" / "routes.yaml", "---\n".join(dump_yaml(o) for o in edge))
        write(out / "edge" / "kustomization.yaml", dump_yaml({
            "apiVersion": "kustomize.config.k8s.io/v1beta1", "kind": "Kustomization",
            "resources": ["routes.yaml"]}))
    write(out / "cicd-env.yaml", dump_yaml({
        "apiVersion": API, "kind": "Environment",
        "app": name, "env": env, "dir": env_dir, "namespace": ns, "branch": branch,
        "hosts": hosts, "image": image, **meta,
    }))
    return out


def build_index(root: Path, cluster: str) -> Path:
    base = root / "envs" / cluster
    entries = []
    if base.exists():
        for k in sorted(base.glob("*/*/kustomization.yaml")):
            d = k.parent
            entries.append(str(d.relative_to(base)))
            if (d / "edge" / "kustomization.yaml").exists():
                entries.append(str((d / "edge").relative_to(base)))
    index = base / "kustomization.yaml"
    write(index, "# Generated by tools/cicd.py index. Every environment CI has rendered on this cluster.\n"
          + dump_yaml({"apiVersion": "kustomize.config.k8s.io/v1beta1", "kind": "Kustomization",
                       "resources": entries}))
    return index


# ---------------------------------------------------------------- promotions


def now_utc() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0)


def parse_time(s: str) -> dt.datetime:
    t = dt.datetime.fromisoformat(s.replace("Z", "+00:00"))
    if t.tzinfo is None:
        sys.exit(f"time {s!r} needs a timezone (use Z for UTC)")
    return t


def request_promotion(root: Path, args) -> Path:
    src = root / "envs" / args.cluster / args.app / args.source
    meta_path = src / "cicd-env.yaml"
    if not meta_path.exists():
        sys.exit(f"no environment at {src}: nothing to promote")
    meta = load_yaml(meta_path)
    not_before = parse_time(args.not_before) if args.not_before else now_utc()
    pid = f"{args.app}-{args.to}-{now_utc().strftime('%Y%m%dT%H%M%SZ')}"
    out = root / "promotions" / "pending" / pid
    out.mkdir(parents=True)
    shutil.copy(src / "app.yaml", out / "app.yaml")  # the exact manifests running in the source env
    shutil.copy(src / "cicd.yaml", out / "cicd.yaml")
    write(out / "promotion.yaml", dump_yaml({
        "apiVersion": API, "kind": "Promotion",
        "id": pid, "app": args.app, "cluster": args.cluster,
        "from": args.source, "to": args.to,
        "image": meta["image"], "commit": meta.get("commit"),
        "notBefore": not_before.isoformat().replace("+00:00", "Z"),
        "requestedBy": args.requested_by or os.environ.get("USER", "unknown"),
        "reason": args.reason or "",
    }))
    print(out)
    return out


def forgejo(method: str, path: str):
    base = os.environ["FORGEJO_API"].rstrip("/")  # e.g. https://forge.example/api/v1/repos/owner/repo
    req = urllib.request.Request(base + path, method=method,
                                 headers={"Authorization": f"token {os.environ['FORGEJO_TOKEN']}",
                                          "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.load(r)


def merged_pr_for(root: Path, sha: str):
    """The merged PR that brought commit `sha` into the current branch. Forgejo answers
    /commits/<sha>/pull only for the commit that landed on the base branch: the merge commit for
    a merge, the commit itself for a rebase or squash. So ask about the commit, then about each
    merge commit that has it as an ancestor, oldest first."""
    merges = subprocess.run(["git", "-C", str(root), "log", "--merges", "--ancestry-path", "--reverse",
                             "--format=%H", f"{sha}..HEAD"], capture_output=True, text=True, check=True).stdout.split()
    errors = []
    for candidate in [sha] + merges:
        try:
            pr = forgejo("GET", f"/commits/{candidate}/pull")
        except Exception as e:  # 404: this commit didn't land through a PR
            errors.append(f"{candidate[:7]}: {e}")
            continue
        if pr.get("merged"):
            return pr, ""
    return None, "; ".join(errors) or "no candidate commits"


def approval_of(root: Path, promo_dir: Path, promo: dict) -> tuple[bool, str]:
    """A promotion counts only if it reached the branch through a merged PR that someone other
    than the PR's author and the requester authorized: an approving review, or the merge itself.
    Branch protection (required approvals) should already enforce this; this is the second check,
    done by the job that actually changes prod."""
    if os.environ.get("CICD_SKIP_APPROVAL_CHECK") == "1":
        return True, "approval check skipped (CICD_SKIP_APPROVAL_CHECK=1)"
    rel = str((promo_dir / "promotion.yaml").relative_to(root))
    sha = subprocess.run(["git", "-C", str(root), "log", "--diff-filter=A", "--format=%H", "-1", "--", rel],
                         capture_output=True, text=True, check=True).stdout.strip()
    if not sha:
        return False, f"{rel} is not committed"
    pr, err = merged_pr_for(root, sha)
    if pr is None:
        return False, f"commit {sha[:7]} did not arrive through a merged pull request ({err})"
    author = pr["user"]["login"]
    excluded = {author, promo.get("requestedBy")}
    reviews = forgejo("GET", f"/pulls/{pr['number']}/reviews")
    approvers = {r["user"]["login"] for r in reviews
                 if r.get("state") == "APPROVED" and not r.get("dismissed") and not r.get("stale")} - excluded
    merger = (pr.get("merged_by") or {}).get("login")
    how = []
    if approvers:
        how.append("approved by " + ", ".join(sorted(approvers)))
    if merger and merger not in excluded:
        how.append(f"merged by {merger}")
    if not how:
        return False, (f"PR #{pr['number']} was approved and merged only by its author/requester "
                       f"({', '.join(sorted(x for x in excluded if x))})")
    return True, f"PR #{pr['number']} " + ", ".join(how)


def apply_due(root: Path, args) -> tuple[int, int]:
    """Returns (applied, refused). A refused promotion is one that is due but failed a check."""
    pending = sorted((root / "promotions" / "pending").glob("*/promotion.yaml"))
    applied = refused = 0
    for p in pending:
        promo = load_yaml(p)
        d = p.parent
        if promo["cluster"] != args.cluster:
            continue
        due = parse_time(promo["notBefore"])
        if due > now_utc():
            print(f"{promo['id']}: not due until {promo['notBefore']}")
            continue
        ok, why = approval_of(root, d, promo)
        if not ok:
            print(f"{promo['id']}: NOT applied: {why}")
            refused += 1
            continue
        app = load_app(str(d / "cicd.yaml"))
        if app["metadata"]["name"] != promo["app"]:
            print(f"{promo['id']}: NOT applied: cicd.yaml names {app['metadata']['name']!r}, not {promo['app']!r}")
            refused += 1
            continue
        cl = load_cluster(root, args.cluster)
        render_env(root, app, cl, promo["to"], None, promo["image"], (d / "app.yaml").read_text(), {
            "commit": promo.get("commit"), "promotion": promo["id"], "approval": why,
            "renderedAt": now_utc().isoformat().replace("+00:00", "Z")},
            app_config_text=(d / "cicd.yaml").read_text())
        done = root / "promotions" / "done" / d.name
        done.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(d), str(done))
        rec = load_yaml(done / "promotion.yaml")
        rec["appliedAt"] = now_utc().isoformat().replace("+00:00", "Z")
        rec["approval"] = why
        write(done / "promotion.yaml", dump_yaml(rec))
        print(f"{promo['id']}: applied ({why})")
        applied += 1
    build_index(root, args.cluster)
    return applied, refused


# ---------------------------------------------------------------- gc


def gc(root: Path, args) -> int:
    heads = subprocess.run(["git", "-C", str(root), "ls-remote", "--heads", args.remote],
                           capture_output=True, text=True, check=True).stdout
    live = {line.split("refs/heads/", 1)[1] for line in heads.splitlines() if "refs/heads/" in line}
    removed = 0
    for meta in sorted((root / "envs" / args.cluster).glob("*/branch-*/cicd-env.yaml")):
        m = load_yaml(meta)
        if m.get("repo", args.repo) != args.repo:
            continue  # another repo's branch environment
        if m.get("branch") not in live:
            print(f"removing {meta.parent} (branch {m.get('branch')!r} is gone)")
            shutil.rmtree(meta.parent)
            removed += 1
    build_index(root, args.cluster)
    return removed


# ---------------------------------------------------------------- cli


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--root", default=".", help="the state repo checkout (default: .)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    h = sub.add_parser("hosts")
    h.add_argument("app")
    h.add_argument("--env", default="branch")
    h.add_argument("--branch")
    h.add_argument("--cluster", required=True)
    h.add_argument("--zone", required=True)

    w = sub.add_parser("which-env", help="print dev, branch or skip for a branch name")
    w.add_argument("app")
    w.add_argument("--branch", required=True)

    r = sub.add_parser("render")
    r.add_argument("app")
    r.add_argument("--env", required=True, choices=["dev", "branch", "prod"])
    r.add_argument("--branch")
    r.add_argument("--cluster", required=True)
    r.add_argument("--image", required=True)
    r.add_argument("--manifests", required=True, help="file with the built app base (kustomize build output)")
    r.add_argument("--commit", default="")
    r.add_argument("--repo", default="")
    r.add_argument("--run-url", default="")

    i = sub.add_parser("index")
    i.add_argument("--cluster", required=True)

    q = sub.add_parser("request-promotion")
    q.add_argument("--app", required=True)
    q.add_argument("--cluster", required=True)
    q.add_argument("--from", dest="source", default="dev")
    q.add_argument("--to", default="prod", choices=["prod"])
    q.add_argument("--not-before")
    q.add_argument("--requested-by")
    q.add_argument("--reason")

    a = sub.add_parser("apply-due")
    a.add_argument("--cluster", required=True)

    g = sub.add_parser("gc")
    g.add_argument("--cluster", required=True)
    g.add_argument("--remote", default="origin", help="git remote (or URL) whose branches count")
    g.add_argument("--repo", default="", help="only collect environments recorded with this repo")

    args = ap.parse_args()
    root = Path(args.root).resolve()

    if args.cmd == "hosts":
        app = load_app(args.app)
        print("\n".join(hosts_for(app, args.env, args.branch, args.cluster, args.zone)))
    elif args.cmd == "which-env":
        app = load_app(args.app)
        if args.branch == app["spec"]["environments"]["dev"]["branch"]:
            print("dev")
        elif branch_wanted(app, args.branch):
            print("branch")
        else:
            print("skip")
    elif args.cmd == "render":
        app = load_app(args.app)
        cl = load_cluster(root, args.cluster)
        out = render_env(root, app, cl, args.env, args.branch, args.image, Path(args.manifests).read_text(), {
            "repo": args.repo, "commit": args.commit, "runUrl": args.run_url,
            "renderedAt": now_utc().isoformat().replace("+00:00", "Z")},
            app_config_text=Path(args.app).read_text())
        build_index(root, args.cluster)
        print(out)
    elif args.cmd == "index":
        print(build_index(root, args.cluster))
    elif args.cmd == "request-promotion":
        request_promotion(root, args)
    elif args.cmd == "apply-due":
        applied, refused = apply_due(root, args)
        print(f"applied {applied}, refused {refused}")
        if refused:
            sys.exit(3)  # the job goes red; anything applied is still written for the caller to commit
    elif args.cmd == "gc":
        print(f"removed {gc(root, args)}")


if __name__ == "__main__":
    main()
