#!/usr/bin/env python3
"""security: run the scanners, normalise their findings, and decide pass/fail by policy.

  scan-source  secrets (gitleaks), code (opengrep) and config (checkov) of an app's tree
  scan-image   SBOM (syft) of a built image, then known vulnerabilities (grype) with the app's VEX
  gate         findings + policy + environment -> security record, ci-result/v1 record, exit code

Every scanner reports and never fails on its own: only `gate` decides. Native scanner output is kept
next to the normalised findings as evidence. Policy is the platform's floor (security/policy.yaml in
this repo); an app's own security/policy.yaml may tighten it and add ignores with a reason and an
expiry date, never loosen it. False positives are handled by those records, never by code changes.

Needs Python 3.10+ and PyYAML; the scanners come from actions/setup.
"""
from __future__ import annotations

import argparse
import datetime as dt
import fnmatch
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import yaml

SCHEMA = "security-findings/v1"
SEVERITY = {"critical": 4, "high": 3, "medium": 2, "low": 1, "negligible": 0, "info": 0, "unknown": 0}
CATEGORIES = ("secrets", "sast", "config", "vuln", "tooling")
ENV_KINDS = ("dev", "branch", "prod")
SOURCE_TOOLS = ("gitleaks", "opengrep", "checkov")
IMAGE_TOOLS = ("syft", "grype")


def now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def finding(category, tool, rule, severity, location, message, **extra) -> dict:
    key = f"{tool}|{rule}|{location}"
    return {"id": hashlib.sha1(key.encode()).hexdigest()[:12], "category": category, "tool": tool,
            "rule": rule, "severity": severity, "location": location, "message": message[:300], **extra}


def run(cmd: list[str], expect: Path | None = None, **kw) -> int:
    """Run a scanner. Its exit code means 'found something' for most of them, so it is only logged.
    If it was meant to write `expect` and didn't, its stderr goes to the job log (stdout)."""
    print("+", " ".join(cmd), file=sys.stderr)
    kw.setdefault("stderr", subprocess.PIPE)
    r = subprocess.run(cmd, **kw)
    err = (r.stderr or b"").decode(errors="replace") if isinstance(r.stderr, bytes) else (r.stderr or "")
    if expect is not None and not expect.exists():
        print(f"{cmd[0]} exited {r.returncode} without writing {expect.name}:")
        print("\n".join("  " + line for line in err.strip().splitlines()[-30:]))
    elif err:
        sys.stderr.write(err)
    return r.returncode


def tool_version(cmd: list[str]) -> str:
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=60).stdout.strip()
        return out.splitlines()[-1].split()[-1] if out else "?"
    except Exception:
        return "?"


# ---------------------------------------------------------------- parsers (native output -> findings)


def parse_gitleaks(path: Path) -> list[dict]:
    out = []
    for r in json.loads(path.read_text() or "[]"):
        loc = f"{r.get('File')}:{r.get('StartLine')}"
        out.append(finding("secrets", "gitleaks", r.get("RuleID", "?"), "high", loc,
                           r.get("Description", "possible secret"),
                           fingerprint=f"{r.get('File')}:{r.get('RuleID')}:{r.get('StartLine')}"))
    return out


def rule_ids(dirs: list[Path]) -> list[str]:
    ids = []
    for d in dirs:
        for f in sorted(d.glob("*.y*ml")):
            ids += [r["id"] for r in (yaml.safe_load(f.read_text()) or {}).get("rules", []) if "id" in r]
    return ids


def parse_opengrep(path: Path, known: list[str] | None = None) -> list[dict]:
    level = {"error": "high", "warning": "medium", "note": "low", "none": "info"}
    out = []
    for run_ in json.loads(path.read_text()).get("runs", []):
        rules = {r["id"]: r for r in run_.get("tool", {}).get("driver", {}).get("rules", [])}
        for r in run_.get("results", []):
            rid = r.get("ruleId", "?")
            lvl = r.get("level") or rules.get(rid, {}).get("defaultConfiguration", {}).get("level", "warning")
            # opengrep prefixes the rule's id with the rule file's directory
            short = next((k for k in sorted(known or [], key=len, reverse=True) if rid == k or rid.endswith("." + k)),
                         rid.split(".rules.", 1)[-1])
            pl = r["locations"][0]["physicalLocation"]
            loc = f"{pl['artifactLocation']['uri']}:{pl.get('region', {}).get('startLine', 0)}"
            out.append(finding("sast", "opengrep", short, level.get(lvl, "medium"), loc,
                               r.get("message", {}).get("text", "")))
    return out


def parse_checkov(path: Path, rel_to: Path | None = None) -> list[dict]:
    data = json.loads(path.read_text() or "{}")
    reports = data if isinstance(data, list) else [data]
    out = []
    for rep in reports:
        for c in rep.get("results", {}).get("failed_checks", []):
            fp = c.get("file_abs_path") or c.get("file_path", "")
            if rel_to is not None and os.path.isabs(fp):
                fp = os.path.relpath(fp, rel_to)
            line = (c.get("file_line_range") or [0])[0]
            # checkov open edition has no severities: a failed check is high, and the platform policy
            # ignores the checks the platform itself takes care of when it renders an environment
            out.append(finding("config", "checkov", c["check_id"], (c.get("severity") or "high").lower(),
                               f"{fp}:{line}", f"{c.get('check_name', '')} ({c.get('resource', '')})"))
    return out


def parse_grype(path: Path) -> list[dict]:
    data = json.loads(path.read_text())
    out = []
    for kind, matches in (("match", data.get("matches", [])), ("ignored", data.get("ignoredMatches", []))):
        for m in matches:
            v, a = m["vulnerability"], m["artifact"]
            fix = v.get("fix", {})
            f = finding("vuln", "grype", v["id"], (v.get("severity") or "unknown").lower(),
                        a.get("purl") or f"{a['name']}@{a['version']}",
                        f"{a['name']} {a['version']} ({a.get('type', '')}): {v.get('description') or v.get('dataSource', '')}",
                        package=a["name"], version=a["version"], fix_state=fix.get("state", "unknown"),
                        fixed_in=fix.get("versions", []))
            if kind == "ignored":
                rules = m.get("appliedIgnoreRules") or [{}]
                f["suppressed"] = {"by": "vex", "reason": rules[0].get("vex-justification") or rules[0].get("reason") or "VEX not_affected/fixed"}
            out.append(f)
    return out


# ---------------------------------------------------------------- scans


def scan_source(args) -> int:
    app = Path(args.app).resolve()
    out = Path(args.out).resolve(); out.mkdir(parents=True, exist_ok=True)
    cicd = Path(__file__).resolve().parent.parent
    findings, tools, evidence = [], {}, {}

    # secrets: the files as they are at this commit. History is the push hook's job.
    gl = out / "gitleaks.json"
    run(["gitleaks", "dir", str(app), "--redact", "--no-banner", "--exit-code", "0", "-f", "json", "-r", str(gl),
         "--gitleaks-ignore-path", str(app)], expect=gl, stdout=subprocess.DEVNULL)
    if gl.exists():
        findings += [dict(f, location=os.path.relpath(f["location"].rsplit(":", 1)[0], app) + ":" + f["location"].rsplit(":", 1)[1],
                          fingerprint=os.path.relpath(f["fingerprint"].split(":", 1)[0], app) + ":" + f["fingerprint"].split(":", 1)[1])
                     for f in parse_gitleaks(gl)]
        tools["gitleaks"] = tool_version(["gitleaks", "version"]); evidence["gitleaks"] = gl.name

    # code: platform rules, plus the app's own if it has any
    og = out / "opengrep.sarif"
    rule_dirs = [cicd / "security" / "rules"] + ([app / "security" / "rules"] if (app / "security" / "rules").is_dir() else [])
    cfg = [x for d in rule_dirs for x in ("--config", str(d))]
    run(["opengrep", "scan", *cfg, "--sarif-output", str(og), "--quiet", "--disable-version-check",
         "--exclude", ".git", "--exclude", ".venv", str(app)], expect=og, stdout=subprocess.DEVNULL,
        stdin=subprocess.DEVNULL, cwd=app)
    if og.exists():
        findings += parse_opengrep(og, rule_ids(rule_dirs))
        tools["opengrep"] = tool_version(["opengrep", "--version"]); evidence["opengrep"] = og.name

    # config: the Dockerfile and the app's built deploy base
    ck = out / "checkov.json"
    targets = []
    if args.dockerfile and Path(args.dockerfile).exists():
        targets += ["-f", str(Path(args.dockerfile).resolve())]
    if args.manifests and Path(args.manifests).exists():
        targets += ["-f", str(Path(args.manifests).resolve())]
    if targets:
        with open(ck, "w") as f:
            run(["checkov", *targets, "--framework", "dockerfile", "kubernetes", "-o", "json", "--quiet",
                 "--compact", "--skip-download"], stdout=f, stderr=subprocess.DEVNULL)
        try:
            findings += parse_checkov(ck, rel_to=Path.cwd())
            tools["checkov"] = tool_version(["checkov", "--version"]); evidence["checkov"] = ck.name
        except json.JSONDecodeError:
            print("checkov output is not JSON; treated as missing", file=sys.stderr)

    return write_findings(out / "findings-source.json", "source", findings, tools, evidence, out, args)


def scan_image(args) -> int:
    out = Path(args.out).resolve(); out.mkdir(parents=True, exist_ok=True)
    src = f"oci-archive:{args.oci_archive}" if args.oci_archive else f"registry:{args.image}"
    env = dict(os.environ)
    if args.insecure_registry:
        env["SYFT_REGISTRY_INSECURE_USE_HTTP"] = "true"
    cdx, spdx = out / "sbom.cdx.json", out / "sbom.spdx.json"
    run(["syft", "scan", src, "-q", "-o", f"cyclonedx-json={cdx}", "-o", f"spdx-json={spdx}",
         "--source-name", args.name or "app"], expect=cdx, env=env)
    findings, tools, evidence = [], {}, {}
    if cdx.exists():
        tools["syft"] = tool_version(["syft", "version"]); evidence["sbom-cyclonedx"] = cdx.name
        evidence["sbom-spdx"] = spdx.name
        gr = out / "grype.json"
        vex = []
        for v in args.vex or []:
            if v and Path(v).exists():
                vex += ["--vex", v]
        run(["grype", f"sbom:{cdx}", *vex, "-q", "-o", "json", "--file", str(gr)], expect=gr, env=env)
        if gr.exists():
            findings += parse_grype(gr)
            tools["grype"] = tool_version(["grype", "version"])
            db = subprocess.run(["grype", "db", "status", "-o", "json"], capture_output=True, text=True).stdout
            try:
                tools["grype-db"] = json.loads(db).get("built", "?")
            except json.JSONDecodeError:
                pass
            evidence["grype"] = gr.name
    return write_findings(out / "findings-image.json", "image", findings, tools, evidence, out, args)


def write_findings(path: Path, scope: str, findings, tools, evidence, out: Path, args) -> int:
    rec = {"schema": SCHEMA, "scope": scope, "generated": now(),
           "commit": os.environ.get("GITHUB_SHA") or getattr(args, "commit", None),
           "image": getattr(args, "image", None) or getattr(args, "digest", None),
           "tools": tools,
           "evidence": {k: {"file": v, "sha256": sha256(out / v)} for k, v in evidence.items()},
           "findings": findings}
    path.write_text(json.dumps(rec, indent=2) + "\n")
    print(f"{path}: {len(findings)} findings from {', '.join(tools) or 'no tools'}")
    return 0


# ---------------------------------------------------------------- policy and gate


def load_policy(platform: Path, app: Path | None) -> tuple[dict, list[str]]:
    """The platform policy with the app's tightenings applied. Returns (policy, notes)."""
    pol = yaml.safe_load(platform.read_text())
    notes = []
    for i in pol.get("ignore", []):
        i.setdefault("owner", "platform")
    if not app or not app.exists():
        return pol, notes
    a = yaml.safe_load(app.read_text()) or {}
    for env, cfg in (a.get("environments") or {}).items():
        if env in pol["environments"] and cfg.get("mode") == "enforce":
            pol["environments"][env]["mode"] = "enforce"
        elif cfg.get("mode") and cfg["mode"] != pol["environments"].get(env, {}).get("mode"):
            notes.append(f"app policy: environments.{env}.mode={cfg['mode']} would loosen the platform's; ignored")
    for cat, cfg in (a.get("categories") or {}).items():
        base = pol["categories"].setdefault(cat, {})
        if "fail_at" in cfg:
            if SEVERITY[cfg["fail_at"]] <= SEVERITY[base.get("fail_at", "critical")]:
                base["fail_at"] = cfg["fail_at"]
            else:
                notes.append(f"app policy: categories.{cat}.fail_at={cfg['fail_at']} would loosen the platform's; ignored")
        if cfg.get("require_fix") is False:
            base["require_fix"] = False  # stricter: unfixed vulnerabilities count too
    for i in a.get("ignore") or []:
        missing = [k for k in ("rule", "reason", "expires") if not i.get(k)]
        if missing:
            notes.append(f"app policy: ignore {i.get('rule')!r} has no {', '.join(missing)}; not applied")
            continue
        pol.setdefault("ignore", []).append(dict(i, owner="app"))
    return pol, notes


def match_ignore(f: dict, ignores: list[dict], today: dt.date):
    """(active ignore, expired ignore) that match this finding."""
    expired = None
    for i in ignores:
        if i.get("category") and i["category"] != f["category"]:
            continue
        if not fnmatch.fnmatch(f["rule"], i["rule"]):
            continue
        if i.get("path") and not fnmatch.fnmatch(f["location"], i["path"]):
            continue
        exp = i.get("expires")
        if exp and dt.date.fromisoformat(str(exp)) < today:
            expired = i
            continue
        return i, None
    return None, expired


def gate(findings: list[dict], pol: dict, env: str, expected: list[str], tools_seen: list[str],
         today: dt.date | None = None) -> dict:
    today = today or dt.datetime.now(dt.timezone.utc).date()
    mode = pol["environments"].get(env, {}).get("mode", "report")
    cats = pol["categories"]
    results = []
    for tool in expected:
        if tool not in tools_seen:
            results.append(finding("tooling", tool, "missing-output", "high", tool,
                                   f"{tool} produced no output, so its category was not checked"))
    for f in findings:
        f = dict(f)
        c = cats.get(f["category"], {})
        if f.get("suppressed"):
            f["outcome"] = "suppressed"
        else:
            active, expired = match_ignore(f, pol.get("ignore", []), today)
            if active:
                f["outcome"] = "suppressed"
                f["suppressed"] = {"by": f"ignore ({active['owner']})", "reason": active["reason"],
                                   "expires": str(active.get("expires", ""))}
            elif SEVERITY.get(f["severity"], 0) < SEVERITY[c.get("fail_at", "high")]:
                f["outcome"] = "below-threshold"
            elif f["category"] == "vuln" and c.get("require_fix", True) and f.get("fix_state") != "fixed":
                f["outcome"] = "no-fix-available"
            else:
                f["outcome"] = "fail"
                if expired:
                    f["expired_ignore"] = {"reason": expired["reason"], "expired": str(expired["expires"])}
        results.append(f)
    for f in results:
        if f["category"] == "tooling":
            f["outcome"] = "fail"
    failing = [f for f in results if f["outcome"] == "fail"]
    blocking = [f for f in failing if mode == "enforce" or cats.get(f["category"], {}).get("always_enforce")]
    status = "fail" if blocking else ("warn" if failing else "pass")
    counts = {}
    for f in results:
        counts.setdefault(f["outcome"], 0)
        counts[f["outcome"]] += 1
    return {"env": env, "mode": mode, "status": status, "blocking": len(blocking), "counts": counts,
            "findings": results}


def load_findings(paths: list[str]) -> tuple[list[dict], list[str], dict]:
    findings, tools, meta = [], [], {}
    for p in paths:
        rec = json.loads(Path(p).read_text())
        findings += rec["findings"]
        tools += list(rec.get("tools", {}))
        meta[rec.get("scope", Path(p).stem)] = {k: rec.get(k) for k in ("generated", "commit", "image", "tools", "evidence")}
    return findings, tools, meta


def cmd_gate(args) -> int:
    pol, notes = load_policy(Path(args.policy), Path(args.app_policy) if args.app_policy else None)
    findings, tools, meta = load_findings(args.findings)
    expected = [t for t in args.expect.split(",") if t] if args.expect else []
    res = gate(findings, pol, args.env, expected, tools)
    res["notes"] = notes
    rec = {"schema": SCHEMA, "app": args.app_name, "image": args.image, "commit": args.commit or os.environ.get("GITHUB_SHA"),
           "generated": now(), "scans": meta, "gate": {k: v for k, v in res.items() if k != "findings"},
           "findings": res["findings"]}
    out = Path(args.out); out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(rec, indent=2) + "\n")
    if args.ci_result:
        write_ci_result(Path(args.ci_result), rec)
    print_summary(rec)
    return 1 if res["status"] == "fail" else 0


def write_ci_result(path: Path, rec: dict):
    """The same ci-result/v1 shape as the test job, so an agent reads every job one way."""
    g = rec["gate"]
    fails = [f for f in rec["findings"] if f["outcome"] == "fail"]
    env = os.environ
    server, repo = env.get("GITHUB_SERVER_URL", ""), env.get("GITHUB_REPOSITORY", "")
    total = len(rec["findings"])
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({
        "schema": "ci-result/v1", "repo": repo, "sha": env.get("GITHUB_SHA") or rec.get("commit"),
        "ref": env.get("GITHUB_REF"), "workflow": env.get("GITHUB_WORKFLOW"), "job": "security",
        "status": g["status"], "started_at": rec["generated"], "duration_s": None,
        "summary": {"total": total, "failed": len(fails), "passed": total - len(fails), "skipped": 0},
        "failures": [{"test": f"{f['category']}/{f['rule']}", "file": f["location"], "severity": f["severity"],
                      "category": f["category"], "message": f["message"]} for f in fails[:50]],
        "security": {"env": g["env"], "mode": g["mode"], "blocking": g["blocking"], "counts": g["counts"],
                     "image": rec.get("image")},
        "run_url": f"{server}/{repo}/actions/runs/{env.get('GITHUB_RUN_NUMBER', '')}" if server else None,
    }, indent=2) + "\n")


def print_summary(rec: dict):
    g = rec["gate"]
    print(f"security gate: {g['status'].upper()} (env {g['env']}, mode {g['mode']}, blocking {g['blocking']}) {g['counts']}")
    for n in g.get("notes", []):
        print(f"  note: {n}")
    order = {"fail": 0, "suppressed": 1, "no-fix-available": 2, "below-threshold": 3}
    shown = [f for f in rec["findings"] if f["outcome"] in ("fail", "suppressed")
             or (f["outcome"] == "no-fix-available" and SEVERITY.get(f["severity"], 0) >= 4)]
    hidden = len(rec["findings"]) - len(shown)
    for f in sorted(shown, key=lambda f: (order.get(f["outcome"], 9), -SEVERITY.get(f["severity"], 0))):
        extra = ""
        if f.get("suppressed"):
            extra = f"  [{f['suppressed']['by']}: {f['suppressed']['reason']}]"
        elif f.get("fixed_in"):
            extra = f"  [fixed in {', '.join(f['fixed_in'])}]"
        if f.get("expired_ignore"):
            extra += f"  [ignore expired {f['expired_ignore']['expired']}]"
        loc = f["location"] if len(f["location"]) < 70 else f"{f.get('package')} {f.get('version')}"
        print(f"  {f['outcome']:<17} {f['severity']:<8} {f['category']:<7} {f['rule']:<28} {loc}{extra}")
    if hidden:
        print(f"  ... {hidden} more below the threshold or without a fix: see the record's findings")


def summary_markdown(rec: dict, limit: int = 30) -> str:
    """A short Markdown table for a pull request body."""
    g = rec["gate"]
    lines = [f"**Security gate: {g['status']}** (environment `{g['env']}`, mode `{g['mode']}`, "
             f"{g['blocking']} blocking). Counts: " + ", ".join(f"{k} {v}" for k, v in sorted(g["counts"].items())), ""]
    shown = [f for f in rec["findings"] if f["outcome"] in ("fail", "suppressed")]
    if shown:
        lines += ["| outcome | severity | category | rule | where | note |", "|---|---|---|---|---|---|"]
        for f in shown[:limit]:
            note = f["suppressed"]["reason"] if f.get("suppressed") else (
                "fixed in " + ", ".join(f["fixed_in"]) if f.get("fixed_in") else "")
            loc = f["location"] if len(f["location"]) < 70 else f"{f.get('package')} {f.get('version')}"
            lines.append(f"| {f['outcome']} | {f['severity']} | {f['category']} | `{f['rule']}` | `{loc}` | {note} |")
    return "\n".join(lines) + "\n"


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan-source")
    s.add_argument("app", help="the app's directory (holds cicd.yaml)")
    s.add_argument("--dockerfile")
    s.add_argument("--manifests", help="the built deploy base (kustomize build output)")
    s.add_argument("--out", default="build/security")
    i = sub.add_parser("scan-image")
    src = i.add_mutually_exclusive_group(required=True)
    src.add_argument("--oci-archive")
    src.add_argument("--image", help="registry reference, e.g. registry:5000/app@sha256:...")
    i.add_argument("--digest", help="the image reference to record (default: --image)")
    i.add_argument("--insecure-registry", action="store_true")
    i.add_argument("--name")
    i.add_argument("--vex", action="append")
    i.add_argument("--out", default="build/security")
    g = sub.add_parser("gate")
    g.add_argument("--findings", action="append", required=True)
    g.add_argument("--env", required=True, choices=ENV_KINDS)
    g.add_argument("--policy", required=True, help="the platform policy (security/policy.yaml)")
    g.add_argument("--app-policy", help="the app's security/policy.yaml, if any")
    g.add_argument("--expect", default=",".join(SOURCE_TOOLS + IMAGE_TOOLS), help="tools whose output must be present")
    g.add_argument("--app-name")
    g.add_argument("--image")
    g.add_argument("--commit")
    g.add_argument("--out", required=True)
    g.add_argument("--ci-result")
    m = sub.add_parser("summary", help="Markdown summary of a security record")
    m.add_argument("record")
    a = ap.parse_args()
    if a.cmd == "scan-source":
        sys.exit(scan_source(a))
    if a.cmd == "scan-image":
        sys.exit(scan_image(a))
    if a.cmd == "gate":
        sys.exit(cmd_gate(a))
    if a.cmd == "summary":
        print(summary_markdown(json.loads(Path(a.record).read_text())), end="")


if __name__ == "__main__":
    main()
