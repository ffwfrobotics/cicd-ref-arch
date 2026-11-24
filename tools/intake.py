#!/usr/bin/env python3
"""intake: check a pushed app against the contract (contract.yaml) before anything is built.

  intake.py check <app dir> --app NAME --dev-branch main [--fill] [--out intake.json] [--github-output]
  intake.py statuses intake.json --repo owner/name --sha SHA [--server URL] [--target-url URL]
  intake.py doc > docs/contract.md

`check` never fails the run. It writes intake.json, a list of {check, rule, state, hint, file,
line}, and says whether there is anything to run (`runnable`). With --fill, what intake can
default (cicd.yaml, the deploy base) is written into the app checkout for this run only and the
check is marked `assumed`; the generated files are printed so they can be committed.

`statuses` posts the result as commit statuses on the app repo (context cicd/contract and
cicd/contract/<check>): developers see them on the commit in the forge, and the dashboard shows
them as the first step of Develop. Needs FORGEJO_TOKEN with write on the app repo.

Needs Python 3.10+ and PyYAML.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
CONTRACT = ROOT / "contract.yaml"
DEFAULT_PORT = 8080


def contract() -> dict:
    return yaml.safe_load(CONTRACT.read_text())


def checks_by_id(c: dict) -> dict[str, dict]:
    return {k["id"]: {**k, "rule": r["n"]} for r in c["rules"] for k in r.get("checks") or []}


# ---------------------------------------------------------------- defaults


def default_cicd(app: str, dev_branch: str, port: int, context: str = ".", dockerfile: str = "Dockerfile") -> dict:
    return {
        "apiVersion": "cicd.ffwf.net/v1alpha1", "kind": "App", "metadata": {"name": app},
        "spec": {
            "build": {"context": context, "dockerfile": dockerfile},
            "deploy": {"path": "deploy"},
            "service": {"name": app, "port": 80},
            "workload": {"kind": "Deployment", "name": app},
            "environments": {
                "dev": {"branch": dev_branch, "host": "{app}-dev.{cluster}.{zone}"},
                "branch": {"host": "{app}-{branch}.{cluster}.{zone}", "exclude": ["promote/*", "renovate/*"]},
                "prod": {"host": "{app}.{cluster}.{zone}", "extraHosts": []},
            },
            "scaleToZero": {"enabled": True, "idleSeconds": 900, "coldStartTimeout": "60s",
                            "maxReplicas": 3, "targetConcurrency": 50},
        },
    }


def default_deploy(app: str, port: int) -> dict[str, str]:
    """templates/app/deploy, named for the app, probing the port with TCP (no path to guess)."""
    deployment = {
        "apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": app},
        "spec": {
            "selector": {"matchLabels": {"app": app}},
            "template": {
                "metadata": {"labels": {"app": app}},
                "spec": {
                    "automountServiceAccountToken": False, "enableServiceLinks": False,
                    "securityContext": {"runAsNonRoot": True, "runAsUser": 65532, "runAsGroup": 65532,
                                        "seccompProfile": {"type": "RuntimeDefault"}},
                    "containers": [{
                        "name": app, "image": "app-image",
                        "ports": [{"name": "http", "containerPort": port}],
                        "readinessProbe": {"tcpSocket": {"port": "http"}, "periodSeconds": 1, "failureThreshold": 3},
                        "livenessProbe": {"tcpSocket": {"port": "http"}, "periodSeconds": 10, "failureThreshold": 6},
                        "resources": {"requests": {"cpu": "10m", "memory": "32Mi"}, "limits": {"memory": "256Mi"}},
                        # a read-only root with a writable /tmp: what the security gate asks (CKV_K8S_22)
                        "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                                            "capabilities": {"drop": ["ALL"]}},
                        "volumeMounts": [{"name": "tmp", "mountPath": "/tmp"}],
                    }],
                    "volumes": [{"name": "tmp", "emptyDir": {"sizeLimit": "64Mi"}}],
                },
            },
        },
    }
    service = {"apiVersion": "v1", "kind": "Service", "metadata": {"name": app},
               "spec": {"selector": {"app": app}, "ports": [{"name": "http", "port": 80, "targetPort": "http"}]}}
    kust = {"apiVersion": "kustomize.config.k8s.io/v1beta1", "kind": "Kustomization",
            "resources": ["deployment.yaml", "service.yaml"]}
    dump = lambda d: yaml.safe_dump(d, sort_keys=False)
    return {"kustomization.yaml": dump(kust), "deployment.yaml": dump(deployment), "service.yaml": dump(service)}


def exposed_port(dockerfile: Path) -> int:
    if dockerfile.is_file():
        m = re.search(r"^\s*EXPOSE\s+(\d+)", dockerfile.read_text(errors="replace"), re.M | re.I)
        if m:
            return int(m.group(1))
    return DEFAULT_PORT


# ---------------------------------------------------------------- check


def line_of(path: Path, pattern: str) -> int | None:
    try:
        for i, line in enumerate(path.read_text(errors="replace").splitlines(), 1):
            if re.search(pattern, line):
                return i
    except OSError:
        pass
    return None


def manifests(deploy: Path) -> list[tuple[Path, dict]]:
    out = []
    for p in sorted(deploy.rglob("*.y*ml")):
        if p.name in ("kustomization.yaml", "kustomization.yml"):
            continue
        try:
            for d in yaml.safe_load_all(p.read_text()):
                if isinstance(d, dict):
                    out.append((p, d))
        except yaml.YAMLError:
            continue
    return out


def pod_specs(docs) -> list[tuple[Path, dict, dict]]:
    """(file, workload, pod spec) for each workload in the base."""
    out = []
    for p, d in docs:
        spec = d.get("spec") or {}
        if d.get("kind") in ("Deployment", "StatefulSet", "DaemonSet", "ReplicaSet"):
            out.append((p, d, ((spec.get("template") or {}).get("spec") or {})))
        elif d.get("kind") == "Pod":
            out.append((p, d, spec))
    return out


def check(app_dir: Path, app: str, dev_branch: str, fill: bool) -> tuple[list[dict], list[tuple[str, str]]]:
    """The results, and the files written to fill gaps (path, content)."""
    c = checks_by_id(contract())
    results: list[dict] = []
    filled: list[tuple[str, str]] = []

    def put(cid: str, state: str, detail: str = "", file: Path | None = None, line: int | None = None):
        k = c[cid]
        results.append({"check": cid, "rule": k["rule"], "state": state,
                        "hint": "" if state == "ok" else k["hint"] + (f" ({detail})" if detail else ""),
                        "file": str(file.relative_to(app_dir)) if file else None, "line": line})

    # 1. cicd.yaml
    cfg_path = app_dir / "cicd.yaml"
    cfg = None
    if cfg_path.is_file():
        try:
            cfg = yaml.safe_load(cfg_path.read_text()) or {}
        except yaml.YAMLError as e:
            put("cicd-yaml", "missing", f"it doesn't parse: {str(e).splitlines()[0]}", cfg_path)
            return results, filled
        named = (cfg.get("metadata") or {}).get("name")
        if named != app:
            put("cicd-yaml", "missing", f"it names {named!r}, enrolled as {app!r}", cfg_path, line_of(cfg_path, r"name:"))
            return results, filled
        put("cicd-yaml", "ok", file=cfg_path)
    else:
        cfg = default_cicd(app, dev_branch, exposed_port(app_dir / "Dockerfile"))
        put("cicd-yaml", "assumed" if fill else "missing")
        if not fill:
            return results, filled
        text = "# generated by intake (tools/intake.py): commit it to change it\n" + yaml.safe_dump(cfg, sort_keys=False)
        cfg_path.write_text(text)
        filled.append(("cicd.yaml", text))
    spec = cfg.get("spec") or {}
    put("tests", "ok" if ((spec.get("test") or {}).get("run") or "").strip() else "warn", file=cfg_path)

    # 9. something to build (checked before the base: its EXPOSE sets the generated port)
    b = spec.get("build") or {}
    # the Dockerfile is named from the IaC root, like the build does (actions/build); the context may be elsewhere
    dockerfile = app_dir / (b.get("dockerfile") or "Dockerfile")
    img = spec.get("image") or {}
    if img:     # prebuilt (docs/enrollment.md): an existing image, pinned by digest, instead of a build
        if img.get("repository") and str(img.get("digest", "")).startswith("sha256:"):
            put("dockerfile", "ok", f"prebuilt {img['repository']}@{img['digest'][:19]}", cfg_path)
            put("base-pinned", "ok", file=cfg_path)
        else:
            put("dockerfile", "missing", "spec.image needs repository and digest (sha256:...)", cfg_path)
        dockerfile = Path("/nonexistent")
    if b.get("dockerfile") and "/" in b["dockerfile"] and not img:
        dockerfile = app_dir / b["dockerfile"]
    if img:
        pass
    elif dockerfile.is_file():
        put("dockerfile", "ok", file=dockerfile)
        lines = dockerfile.read_text(errors="replace").splitlines()
        args = dict(m.groups() for l in lines if (m := re.match(r"\s*ARG\s+(\w+)=(\S+)", l, re.I)))
        expand = lambda l: re.sub(r"\$\{?(\w+)\}?", lambda m: args.get(m.group(1), m.group(0)), l)
        froms = [(i, expand(l)) for i, l in enumerate(lines, 1) if re.match(r"\s*FROM\s", l, re.I)]
        stages = {m.group(1).lower() for _, l in froms if (m := re.search(r"\sAS\s+(\S+)", l, re.I))}
        unpinned = [(i, l) for i, l in froms
                    if "@sha256:" not in l and l.split()[1].lower() not in stages and l.split()[1].lower() != "scratch"
                    and not l.split()[1].startswith("--")]
        if unpinned:
            put("base-pinned", "warn", unpinned[0][1].strip(), dockerfile, unpinned[0][0])
        else:
            put("base-pinned", "ok", file=dockerfile)
    else:
        put("dockerfile", "missing", f"looked for {dockerfile.relative_to(app_dir)}")

    # 2. the deploy base
    deploy = app_dir / ((spec.get("deploy") or {}).get("path") or "deploy")
    if (deploy / "kustomization.yaml").is_file() or (deploy / "kustomization.yml").is_file():
        put("deploy-base", "ok", file=deploy)
    elif fill and not deploy.exists():
        deploy.mkdir(parents=True)
        for name, text in default_deploy(app, exposed_port(dockerfile)).items():
            (deploy / name).write_text(text)
            filled.append((str((deploy / name).relative_to(app_dir)), text))
        put("deploy-base", "assumed")
    else:
        put("deploy-base", "missing", f"no kustomization.yaml in {deploy.relative_to(app_dir)}/")
        return results, filled
    docs = manifests(deploy)

    ns = [(p, d) for p, d in docs if (d.get("metadata") or {}).get("namespace")]
    put("no-namespace", "warn" if ns else "ok", *((ns[0][1]["metadata"]["namespace"], ns[0][0],
        line_of(ns[0][0], r"namespace:")) if ns else ()))

    pods = pod_specs(docs)
    containers = [(p, ctr) for p, _, ps in pods for ctr in ps.get("containers") or []]
    if not any(ctr.get("image") == "app-image" for _, ctr in containers):
        img = next((ctr.get("image") for _, ctr in containers), None)
        put("app-image", "warn", f"found {img}" if img else "no container", *((containers[0][0],
            line_of(containers[0][0], r"image:")) if containers else ()))
    else:
        put("app-image", "ok")

    reps = [(p, d) for p, d, _ in pods if "replicas" in (d.get("spec") or {})]
    put("no-replicas", "warn" if reps else "ok", *(("", reps[0][0], line_of(reps[0][0], r"^\s*replicas:")) if reps else ()))

    lacking = []
    for p, _, ps in pods:
        psc = ps.get("securityContext") or {}
        for ctr in ps.get("containers") or []:
            sc = ctr.get("securityContext") or {}
            if not (sc.get("runAsNonRoot", psc.get("runAsNonRoot"))):
                lacking.append("runAsNonRoot")
            if ((sc.get("seccompProfile") or psc.get("seccompProfile") or {}).get("type")) not in ("RuntimeDefault", "Localhost"):
                lacking.append("seccompProfile")
            if sc.get("allowPrivilegeEscalation") is not False:
                lacking.append("allowPrivilegeEscalation: false")
            if "ALL" not in ((sc.get("capabilities") or {}).get("drop") or []):
                lacking.append("capabilities.drop: [ALL]")
    lacking = list(dict.fromkeys(lacking))
    put("restricted", "warn" if lacking else "ok", ", ".join(lacking), pods[0][0] if pods and lacking else None)

    no_probe = [ctr.get("name") for _, ctr in containers if not ctr.get("readinessProbe")]
    put("readiness", "warn" if no_probe else "ok", ", ".join(map(str, no_probe)),
        containers[0][0] if no_probe else None)

    no_req = [ctr.get("name") for _, ctr in containers if not (ctr.get("resources") or {}).get("requests")]
    put("requests", "warn" if no_req else "ok", ", ".join(map(str, no_req)), containers[0][0] if no_req else None)

    overlay_check(app_dir, deploy, spec, put)
    drift_check(app_dir, put)

    want = spec.get("service") or {}
    svcs = {(d.get("metadata") or {}).get("name"): (p, d) for p, d in docs if d.get("kind") == "Service"}
    if want.get("name") not in svcs:
        put("service", "warn", f"no Service {want.get('name')!r} in the base")
    elif int(want.get("port") or 0) not in [int(x.get("port") or 0) for x in (svcs[want["name"]][1].get("spec") or {}).get("ports") or []]:
        p = svcs[want["name"]][0]
        put("service", "warn", f"Service {want['name']} has no port {want.get('port')}", p, line_of(p, r"port:"))
    else:
        put("service", "ok")
    return results, filled


OVERLAY_ENVS = ("dev", "branch", "prod")
# what an allowlist entry in spec.overlays.allow permits an overlay to change (paths in the rendered objects)
ALLOW = {
    "resources": lambda p: ".resources" in p,
    "replicas": lambda p: p.endswith("spec.replicas"),
    "env": lambda p: ".env[" in p or ".env." in p or p.endswith(".env") or ".envFrom" in p,
    "labels": lambda p: ".labels" in p,
    "annotations": lambda p: ".annotations" in p,
    "probes": lambda p: "Probe" in p,
}


def kustomize(d: Path) -> tuple[list[dict] | None, str]:
    cmd = ["kustomize", "build", str(d)] if shutil.which("kustomize") else ["kubectl", "kustomize", str(d)]
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        return None, (r.stderr.strip().splitlines() or ["kustomize failed"])[-1][:160]
    return [x for x in yaml.safe_load_all(r.stdout) if isinstance(x, dict)], ""


def flat(obj, prefix="") -> dict[str, object]:
    out = {}
    if isinstance(obj, dict):
        for k, v in obj.items():
            out.update(flat(v, f"{prefix}.{k}" if prefix else str(k)))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            key = (v.get("name") if isinstance(v, dict) and "name" in v else i)
            out.update(flat(v, f"{prefix}[{key}]"))
    else:
        out[prefix] = obj
    return out


DRIFT_GLOBS = ("deploy/**/*", "deploy-*/**/*", "cicd.yaml", "Dockerfile", "Containerfile")


def source_files(src: Path) -> dict[str, str]:
    """sha256 of the source's own deploy files: what a wrapped app ignores, and so watches."""
    import hashlib
    out = {}
    for g in DRIFT_GLOBS:
        for p in sorted(src.glob(g)):
            if p.is_file():
                out[str(p.relative_to(src))] = hashlib.sha256(p.read_bytes()).hexdigest()
    return out


def drift_check(app_dir: Path, put):
    """A wrapped app ignores its source's own deploy/, cicd.yaml and Dockerfile (docs/enrollment.md). When
    those change after wrapping, say which: the developers may have meant something the IaC root should get."""
    base = app_dir / ".wrap" / "source-files.json"
    if not base.is_file():
        return
    rec = json.loads(base.read_text())
    src = app_dir / rec.get("source", "src")
    now = source_files(src)
    then = rec.get("files") or {}
    changed = sorted(p for p in set(now) | set(then) if now.get(p) != then.get(p))
    if changed:
        put("source-drift", "warn", ", ".join(f"{rec.get('source', 'src')}/{p}" for p in changed[:6])
            + (f" and {len(changed) - 6} more" if len(changed) > 6 else ""), base)
    else:
        put("source-drift", "ok")


def overlay_check(app_dir: Path, deploy: Path, spec: dict, put):
    """deploy-<env>/ overlays (docs/enrollment.md): each must build, pass the base's pod checks, and change only
    what spec.overlays.allow names (when it names anything). Checked on every push, whatever env this run deploys,
    so a broken prod overlay fails the push that broke it, not the promotion."""
    found = [d for d in (app_dir / f"deploy-{e}" for e in OVERLAY_ENVS) if (d / "kustomization.yaml").is_file()]
    if not found:
        put("overlays", "ok")
        return
    allow = ((spec.get("overlays") or {}).get("allow")) or []
    base, _ = kustomize(deploy)
    base_flat = {(o.get("kind"), (o.get("metadata") or {}).get("name")): flat(o) for o in base or []}
    broken, problems = [], []
    for d in found:
        docs, err = kustomize(d)
        if docs is None:
            broken.append(f"{d.name}/: {err}")
            continue
        for o in docs:
            if (o.get("metadata") or {}).get("namespace"):
                problems.append(f"{d.name}/ sets a namespace")
        for _, _, ps in pod_specs([(d, o) for o in docs]):
            for ctr in ps.get("containers") or []:
                if not (ctr.get("resources") or {}).get("requests"):
                    problems.append(f"{d.name}/ drops resources.requests")
                sc = ctr.get("securityContext") or {}
                if sc.get("allowPrivilegeEscalation") is not False or "ALL" not in ((sc.get("capabilities") or {}).get("drop") or []):
                    problems.append(f"{d.name}/ loosens the container securityContext")
        if allow:
            for o in docs:
                key = (o.get("kind"), (o.get("metadata") or {}).get("name"))
                before, after = base_flat.get(key, {}), flat(o)
                changed = [p for p in set(before) | set(after) if before.get(p) != after.get(p)]
                bad = [p for p in changed if not any(ALLOW.get(a, lambda _: False)(p) for a in allow)]
                if bad:
                    problems.append(f"{d.name}/ changes {sorted(bad)[0]} (allowed: {', '.join(allow)})")
    names = ", ".join(d.name + "/" for d in found)
    if broken:
        put("overlays", "missing", "; ".join(broken), found[0])
    elif problems:
        put("overlays", "warn", "; ".join(dict.fromkeys(problems)), found[0])
    else:
        put("overlays", "ok", names)


def runnable(results: list[dict]) -> bool:
    return not any(r["state"] == "missing" for r in results)


def summary(results: list[dict]) -> str:
    bad = [r for r in results if r["state"] != "ok"]
    if not runnable(results):
        first = next(r for r in results if r["state"] == "missing")
        return first["hint"]
    if not bad:
        return "meets the contract"
    n_warn = sum(r["state"] == "warn" for r in bad)
    n_ass = sum(r["state"] == "assumed" for r in bad)
    return ", ".join(x for x in (f"{n_warn} to fix" if n_warn else "", f"{n_ass} assumed" if n_ass else "") if x)


# ---------------------------------------------------------------- statuses


STATE = {"ok": "success", "assumed": "warning", "warn": "warning", "missing": "failure"}


def post_statuses(results: list[dict], server: str, repo: str, sha: str, target: str, token: str) -> int:
    def post(context: str, state: str, description: str) -> int:
        body = json.dumps({"context": context, "state": state, "description": description[:250],
                           "target_url": target}).encode()
        req = urllib.request.Request(f"{server.rstrip('/')}/api/v1/repos/{repo}/statuses/{sha}", data=body,
                                     method="POST", headers={"Authorization": f"token {token}",
                                                             "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=20) as r:
                return r.status
        except urllib.error.HTTPError as e:
            return e.code
    overall = "failure" if not runnable(results) else "warning" if any(r["state"] != "ok" for r in results) else "success"
    code = post("cicd/contract", overall, summary(results))
    if code not in (200, 201):
        return code
    for r in results:
        if r["state"] != "ok":
            where = f" [{r['file']}{':' + str(r['line']) if r['line'] else ''}]" if r["file"] else ""
            post(f"cicd/contract/{r['check']}", STATE[r["state"]], f"rule {r['rule']}: {r['hint']}{where}")
    return code


# ---------------------------------------------------------------- doc


def doc() -> str:
    c = contract()
    out = ["# The app contract", "",
           "<!-- generated from contract.yaml by `tools/intake.py doc`: edit that file, not this one -->", "",
           "An app that meets these points deploys through this pipeline with no platform changes.", "",
           "| # | Rule | Why |", "|---|---|---|"]
    out += [f"| {r['n']} | {r['rule']} | {r['why']} |" for r in c["rules"]]
    out += ["", c["secrets"], "", "## What the pipeline checks on each push", "",
            "The `intake` step (`tools/intake.py`) checks each pushed commit before anything is built, and "
            "posts the result as commit statuses (`cicd/contract`, and `cicd/contract/<check>` for each one "
            "that isn't ok). It never fails the run by itself:",
            "- **assumed**: missing, so a default is used for this run and printed in the log, to commit;",
            "- **warn**: the pipeline goes on, and the hint says what to change;",
            "- **missing**: there is nothing to run, so the run stops after intake.", "",
            "| Check | Rule | What | When it doesn't hold |", "|---|---|---|---|"]
    for r in c["rules"]:
        for k in r.get("checks") or []:
            when = "missing: stops the run" if k.get("stops") else "assumed: default used" if k.get("fill") else "warn"
            out.append(f"| `{k['id']}` | {r['n']} | {k['what']} | {when}. {k['hint']} |")
    out += ["", "## After the deploy: the runtime check", "",
            "The `runtime` job (`tools/runtime.py`) waits for the environment to run the new build, sends one "
            "request to its host (which also wakes a scaled-to-zero app), and watches the build's pods for about "
            "90 s. It posts one word as the commit status `cicd/runtime`, and keeps the pod states, events and "
            "last log lines it decided from with the run (artifact `runtime`).", "",
            "| Word | Rule | What it saw | What to do |", "|---|---|---|---|"]
    for k in c["runtime"]:
        out.append(f"| **{k['keyword']}** | {k.get('rule') or ''} | {k['what']} | {k['hint']} |")
    return "\n".join(out) + "\n"


# ---------------------------------------------------------------- cli


def main():
    import cicd  # instance.yaml's names (forge_url)

    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    ck = sub.add_parser("check")
    ck.add_argument("app_dir")
    ck.add_argument("--app", required=True)
    ck.add_argument("--dev-branch", default="main", help="for a generated cicd.yaml: the repo's default branch")
    ck.add_argument("--fill", action="store_true", help="write defaults for what can be defaulted")
    ck.add_argument("--out", help="write intake.json here")
    ck.add_argument("--github-output", action="store_true", help="append runnable=true|false to $GITHUB_OUTPUT")
    ck.add_argument("--quiet", action="store_true")
    st = sub.add_parser("statuses")
    st.add_argument("intake_json")
    st.add_argument("--repo", required=True)
    st.add_argument("--sha", required=True)
    st.add_argument("--server", default=cicd.forge_url(), help="the forge (default: instance.yaml forge_url)")
    st.add_argument("--target-url", default="")
    sub.add_parser("doc")
    a = ap.parse_args()

    if a.cmd == "doc":
        sys.stdout.write(doc())
        return
    if a.cmd == "statuses":
        results = json.loads(Path(a.intake_json).read_text())["results"]
        token = os.environ.get("FORGEJO_TOKEN", "")
        code = post_statuses(results, a.server, a.repo, a.sha, a.target_url, token) if token else 0
        if code not in (200, 201):
            print(f"::notice::contract statuses not posted on {a.repo} ({code or 'no token'}): the bot needs write on it")
        return

    results, filled = check(Path(a.app_dir), a.app, a.dev_branch, a.fill)
    ok = runnable(results)
    if a.out:
        Path(a.out).write_text(json.dumps({"runnable": ok, "summary": summary(results), "results": results}, indent=1))
    if a.github_output and os.environ.get("GITHUB_OUTPUT"):
        with open(os.environ["GITHUB_OUTPUT"], "a") as f:
            f.write(f"runnable={'true' if ok else 'false'}\nsummary={summary(results)}\n")
    if a.quiet:
        return
    print(f"contract: {summary(results)}")
    for r in results:
        where = f"  {r['file']}{':' + str(r['line']) if r['line'] else ''}" if r["file"] and r["state"] != "ok" else ""
        print(f"  {r['state']:8} {r['check']:14} {r['hint']}{where}")
        if r["state"] == "missing":
            print(f"::error::{r['hint']}")
        elif r["state"] != "ok":
            print(f"::warning::{r['hint']}")
    for path, text in filled:
        print(f"\n--- generated {path} (commit it to change it) ---\n{text}")


if __name__ == "__main__":
    main()
