#!/usr/bin/env python3
"""oscal: the owner's continuous self-assessment, in OSCAL (docs/oscal.md).

  excerpt     cut the NIST SP 800-53 catalog down to a profile's controls (with 800-53A objectives)
  component   compile a layer (platform, app or sysadmin YAML) to an OSCAL component-definition
  ssp         the app's system security plan, from its profile and the three layers
  assess      evidence of one commit's build + the layers -> OSCAL assessment-results, and a short
              summary for the dashboard (assessment-summary.json)

Layers, merged objective by objective in this order (a later one replaces an earlier one):
  1. platform  oscal/platform.yaml here: what the pipeline implements for every app
  2. app       oscal/component.yaml in the app's repo, if its developers keep one (never required)
  3. sysadmin  apps/<app>/component.yaml in the compliance repo: the owner's sysadmins, for what
               the pipeline can't see, overrides, and legacy apps with nothing in their repo

Each objective names evidence selectors: what kind of record proves it. The vocabulary is ours,
carried as props in https://ffwf.net/ns/cicd until a spec exists:
  sbom | scan {tool} | findings {category} | ci-result {job} | gate | vuln-db {max_age_h}
  | manifests | config-control | release {within_days} | attested {name, by, at, expires, note}
An objective may instead be `not-applicable: <reason>`. With no statement in any layer it is
`uncovered`. These results are the owner's self-assessment (metadata prop assessment-kind), not
an official assessment: those come from the assessor (the CSPD app).

Needs Python 3.10+ and PyYAML.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import re
import sys
import uuid
from pathlib import Path

import yaml


def _instance() -> dict:
    """instance.yaml at the repo root (tools/cicd.py instance())."""
    p = Path(__file__).resolve().parent.parent / "instance.yaml"
    return (yaml.safe_load(p.read_text()) or {}) if p.exists() else {}

NS = "https://ffwf.net/ns/cicd"
OSCAL_VERSION = "1.2.3"
UUID_NS = uuid.UUID("5d0f3c38-3f0e-4f43-9a8e-7b0c1c2d9e11")
LAYERS = ("platform", "app", "sysadmin")
AUTOMATED = {"sbom", "scan", "findings", "ci-result", "gate", "vuln-db", "manifests", "config-control", "release"}


def now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def uid(*parts) -> str:
    return str(uuid.uuid5(UUID_NS, "|".join(map(str, parts))))


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def prop(name: str, value, cls: str | None = None) -> dict:
    p = {"name": name, "ns": NS, "value": str(value)}
    if cls:
        p["class"] = cls
    return p


def metadata(title: str, **extra) -> dict:
    return {"title": title, "last-modified": now(), "version": extra.pop("version", "1"), "oscal-version": OSCAL_VERSION, **extra}


def odp_free(text: str) -> str:
    return re.sub(r"\{\{\s*insert:\s*param,\s*([^}\s]+)\s*\}\}", r"[\1]", text or "").strip()


# ---------------------------------------------------------------- catalog and profile


def walk_controls(ctrls):
    for c in ctrls or []:
        yield c
        yield from walk_controls(c.get("controls"))


def catalog_controls(catalog: dict) -> dict[str, dict]:
    out = {}
    for g in catalog["catalog"].get("groups", []):
        for c in walk_controls(g.get("controls")):
            out[c["id"]] = c
    for c in walk_controls(catalog["catalog"].get("controls")):
        out[c["id"]] = c
    return out


def leaf_objectives(control: dict) -> list[tuple[str, str]]:
    """(objective id, prose) of the 800-53A objectives with no sub-objectives, in document order."""
    out = []

    def walk(parts):
        for p in parts or []:
            if p.get("name") == "assessment-objective":
                kids = [q for q in p.get("parts") or [] if q.get("name") == "assessment-objective"]
                if not kids:
                    out.append((p["id"], odp_free(p.get("prose", ""))))
            walk(p.get("parts"))
    walk(control.get("parts"))
    return out


def profile_controls(profile: dict) -> list[str]:
    ids = []
    for imp in profile["profile"]["imports"]:
        for inc in imp.get("include-controls", []):
            ids += inc.get("with-ids", [])
    return ids


def objectives_for(catalog: dict, control_ids: list[str]) -> list[dict]:
    ctrls = catalog_controls(catalog)
    out = []
    for cid in control_ids:
        c = ctrls[cid]
        for oid, prose in leaf_objectives(c):
            out.append({"id": oid, "control": cid, "control_title": c["title"], "prose": prose})
    return out


def cmd_excerpt(a) -> int:
    full = json.loads(Path(a.catalog).read_text())
    want = set(profile_controls(json.loads(Path(a.profile).read_text())))
    groups = []
    for g in full["catalog"]["groups"]:
        keep = []
        for c in walk_controls(g.get("controls")):
            if c["id"] in want:
                keep.append({k: v for k, v in c.items() if k != "controls"})
        if keep:
            groups.append({"id": g["id"], "class": g.get("class", "family"), "title": g["title"], "controls": keep})
    m = full["catalog"]["metadata"]
    out = {"catalog": {"uuid": uid("catalog-excerpt", *sorted(want), m["version"]),
                       "metadata": {**metadata(f"Excerpt of {m['title']}", version=m["version"]),
                                    "oscal-version": m["oscal-version"],
                                    "props": [prop("source", a.source), prop("source-sha256", sha256(Path(a.catalog)))],
                                    "remarks": "Unaltered control and objective text, cut down to the profile's controls."},
                       "groups": groups}}
    Path(a.out).write_text(json.dumps(out, indent=1) + "\n")
    print(f"{a.out}: {sum(len(g['controls']) for g in groups)} controls")
    return 0


# ---------------------------------------------------------------- layers


def load_layer(path: str | None, layer: str) -> dict | None:
    if not path or not Path(path).exists():
        return None
    d = yaml.safe_load(Path(path).read_text()) or {}
    d["layer"] = layer
    d["path"] = path
    return d


def merged(layers: list[dict]) -> dict[str, dict]:
    """objective id -> its statement from the last layer that has one, with that layer's name."""
    out = {}
    for L in layers:
        for oid, st in (L.get("objectives") or {}).items():
            out[oid] = dict(st, layer=L["layer"], component=L.get("component", L["layer"]))
    return out


def selector_key(sel: dict) -> str:
    return sel["kind"] + "".join(f":{k}={v}" for k, v in sorted(sel.items()) if k not in ("kind", "note", "by", "at", "expires"))


def cmd_component(a) -> int:
    L = load_layer(a.layer, a.kind)
    if L is None:
        sys.exit(f"no layer at {a.layer}")
    print(json.dumps(component_definition(L, a.source), indent=1))
    return 0


def component_definition(L: dict, source: str) -> dict:
    by_control: dict[str, list] = {}
    for oid, st in (L.get("objectives") or {}).items():
        by_control.setdefault(oid.split("_obj")[0], []).append((oid, st))
    reqs = []
    for cid, items in sorted(by_control.items()):
        props = []
        lines = []
        for oid, st in items:
            if st.get("not-applicable"):
                props.append(prop("not-applicable", st["not-applicable"], oid))
                lines.append(f"{oid}: not applicable: {st['not-applicable']}")
                continue
            for sel in st.get("evidence", []):
                props.append(prop("evidence-selector", selector_key(sel), oid))
            lines.append(f"{oid}: {st.get('statement', '')}")
        reqs.append({"uuid": uid(L["component"], cid), "control-id": cid, "description": "\n".join(lines), "props": props})
    return {"component-definition": {
        "uuid": uid("component-definition", L["component"], L["layer"]),
        "metadata": metadata(f"{L.get('title', L['component'])} ({L['layer']} layer)",
                             props=[prop("layer", L["layer"])]),
        "components": [{
            "uuid": uid("component", L["component"]), "type": L.get("type", "software"),
            "title": L.get("title", L["component"]), "description": (L.get("description") or L.get("title", L["component"])).strip(),
            "props": [prop("layer", L["layer"])],
            "control-implementations": [{"uuid": uid("ci", L["component"], source), "source": source,
                                         "description": f"Objective-level statements of the {L['layer']} layer.",
                                         "implemented-requirements": reqs}]}]}}


# ---------------------------------------------------------------- evidence of one commit


class Evidence:
    """What one build left behind: the security record, SBOM, ci-result records, manifests."""

    def __init__(self, d: Path, releases: Path | None, app: str, today: dt.datetime | None = None,
                 commit: str | None = None, image: str | None = None):
        self.dir, self.app, self.commit, self.image = d, app, commit, image
        self.now = today or dt.datetime.now(dt.timezone.utc)
        self.files = {}
        for name in ("security.json", "security-record.json", "sbom.cdx.json", "ci-result-test.json",
                     "ci-result-security.json", "app.yaml"):
            p = d / name
            if p.exists():
                self.files[name] = p
        rec = self.files.get("security.json") or self.files.get("security-record.json")
        self.record = json.loads(rec.read_text()) if rec else None
        self.sbom = json.loads(self.files["sbom.cdx.json"].read_text()) if "sbom.cdx.json" in self.files else None
        self.ci = {j: json.loads(self.files[f"ci-result-{j}.json"].read_text())
                   for j in ("test", "security") if f"ci-result-{j}.json" in self.files}
        self.releases = []
        if releases and releases.is_dir():
            for m in sorted(releases.glob("*/manifest.json")):
                try:
                    self.releases.append(json.loads(m.read_text()))
                except json.JSONDecodeError:
                    pass

    def href(self, name: str) -> dict | None:
        p = self.files.get(name)
        if p is None:
            return None
        return {"href": name, "description": f"{name} kept with this commit's environment",
                "props": [prop("sha256", sha256(p))]}

    def tools(self) -> dict:
        out = {}
        for scope in ((self.record or {}).get("scans") or {}).values():
            out.update((scope or {}).get("tools") or {})
        return out

    def evaluate(self, sel: dict) -> tuple[bool, str, list[dict]]:
        """(holds, what was found, relevant evidence)"""
        k = sel["kind"]
        rec = self.record or {}
        if k == "sbom":
            n = len((self.sbom or {}).get("components") or [])
            return n > 0, f"SBOM with {n} components" if self.sbom else "no SBOM kept for this commit", [x for x in [self.href("sbom.cdx.json")] if x]
        if k == "scan":
            t = sel["tool"]
            v = self.tools().get(t)
            return bool(v), f"{t} {v} ran" if v else f"{t} produced no output", [x for x in [self.href("security.json") or self.href("security-record.json")] if x]
        if k == "gate":
            g = rec.get("gate")
            return bool(g), (f"gate {g['status']} in {g['env']} ({g['mode']})" if g else "no gate record"), [x for x in [self.href("security.json") or self.href("security-record.json")] if x]
        if k == "findings":
            cat = sel.get("category", "all")
            if not rec:
                return False, "no security record", []
            fails = [f for f in rec.get("findings", []) if f.get("outcome") == "fail" and (cat == "all" or f["category"] == cat)]
            what = "findings" if cat == "all" else f"{cat} findings"
            if fails:
                ids = ", ".join(sorted({f["rule"] for f in fails})[:4])
                return False, f"{len(fails)} {what} would block prod: {ids}", [self.href("security.json") or self.href("security-record.json")]
            return True, f"no {what} at or above the prod threshold", [x for x in [self.href("security.json") or self.href("security-record.json")] if x]
        if k == "ci-result":
            j = sel["job"]
            r = self.ci.get(j)
            if r is None:
                return False, f"no ci-result for {j}", []
            s = r.get("summary") or {}
            # tests must pass; the security job only has to have run (its findings are judged by `findings`)
            ok = r.get("status") in ("pass", "warn", "fail") if j == "security" else r.get("status") == "pass"
            return ok, f"{j} ran: {r.get('status')} ({s.get('passed', '?')}/{s.get('total', '?')} checks passed)", [self.href(f"ci-result-{j}.json")]
        if k == "vuln-db":
            built = self.tools().get("grype-db")
            if not built:
                return False, "vulnerability database time not recorded", []
            try:
                t = dt.datetime.fromisoformat(str(built).replace("Z", "+00:00"))
            except ValueError:
                return False, f"unreadable database time {built!r}", []
            age = (self.now - t).total_seconds() / 3600
            return age <= sel.get("max_age_h", 48), f"grype database built {built} ({age:.0f} h old)", []
        if k == "manifests":
            return "app.yaml" in self.files, "rendered manifests kept in git" if "app.yaml" in self.files else "no manifests kept", [x for x in [self.href("app.yaml")] if x]
        if k == "config-control":
            commit, image = self.commit or rec.get("commit") or "", self.image or rec.get("image") or ""
            ok = bool(re.fullmatch(r"[0-9a-f]{40}", commit)) and "@sha256:" in image
            return ok, f"commit {commit[:12]}, image pinned by digest" if ok else "commit or digest missing", []
        if k == "release":
            days = sel.get("within_days", 30)
            recent = [r for r in self.releases if self.app in (r.get("apps") or [])
                      and r.get("released") and (self.now - dt.datetime.fromisoformat(r["released"].replace("Z", "+00:00"))).days <= days]
            if recent:
                r = recent[-1]
                return True, f"release {r['id']} to IT Security on {r['released'][:10]}", []
            return False, f"nothing released to IT Security in the last {days} days", []
        if k == "attested":
            exp = sel.get("expires")
            if exp and dt.date.fromisoformat(str(exp)) < self.now.date():
                return False, f"{sel.get('name', 'attestation')} by {sel.get('by')} expired {exp}", []
            return True, f"{sel.get('name', 'attested')} by {sel.get('by')} on {sel.get('at')}" + (f": {sel['note']}" if sel.get("note") else ""), []
        return False, f"unknown evidence kind {k!r}", []


def assess(objs: list[dict], stmts: dict[str, dict], ev: Evidence, meta: dict) -> tuple[dict, dict]:
    generated = now()
    observations: dict[str, dict] = {}
    findings, summary_rows = [], []
    for o in objs:
        st = stmts.get(o["id"])
        row = {"id": o["id"], "control": o["control"], "objective": o["prose"][:200]}
        obs_ids = []
        if st is None:
            row.update(layer=None, coverage="uncovered", state="not-satisfied", reason="no implementation statement in any layer", evidence=[])
        elif st.get("not-applicable"):
            row.update(layer=st["layer"], coverage="not-applicable", state="satisfied", reason=st["not-applicable"], evidence=[])
        else:
            details, ok_all, kinds = [], True, set()
            for sel in st.get("evidence") or []:
                key = selector_key(sel)
                ok, what, hrefs = ev.evaluate(sel)
                kinds.add(sel["kind"])
                ok_all &= ok
                details.append({"selector": key, "holds": ok, "found": what})
                if key not in observations:
                    observations[key] = {
                        "uuid": uid(meta["app"], meta["commit"], generated, key),
                        "title": key, "description": what,
                        "props": [prop("evidence-selector", key), prop("holds", str(ok).lower())],
                        "methods": ["EXAMINE"] if sel["kind"] == "attested" else ["TEST"],
                        "types": ["control-objective"], "collected": generated,
                        **({"relevant-evidence": [h for h in hrefs if h]} if any(hrefs) else {})}
                obs_ids.append(observations[key]["uuid"])
            if not details:
                ok_all = False
                details.append({"selector": None, "holds": False, "found": "statement names no evidence"})
            coverage = "automated" if kinds and kinds <= AUTOMATED else "manual"
            row.update(layer=st["layer"], coverage=coverage, state="satisfied" if ok_all else "not-satisfied",
                       reason=st.get("statement", ""), evidence=details)
        summary_rows.append(row)
        f = {"uuid": uid(meta["app"], meta["commit"], generated, o["id"]),
             "title": f"{o['id']}: {row['state']}",
             "description": row["reason"] or o["prose"],
             "props": [prop("coverage", row["coverage"])] + ([prop("layer", row["layer"])] if row["layer"] else []),
             "target": {"type": "objective-id", "target-id": o["id"],
                        "status": {"state": row["state"], **({"reason": "not-applicable"} if row["coverage"] == "not-applicable" else {})}}}
        if obs_ids:
            f["related-observations"] = [{"observation-uuid": u} for u in dict.fromkeys(obs_ids)]
        findings.append(f)

    controls = list(dict.fromkeys(o["control"] for o in objs))
    counts = {"satisfied": sum(r["state"] == "satisfied" for r in summary_rows),
              "not-satisfied": sum(r["state"] == "not-satisfied" for r in summary_rows)}
    coverage = {}
    for r in summary_rows:
        coverage[r["coverage"]] = coverage.get(r["coverage"], 0) + 1
    title = f"Self-assessment of {meta['app']} at {meta['commit'][:12]} ({meta['env']})"
    ar = {"assessment-results": {
        "uuid": uid("ar", meta["app"], meta["env"], meta["commit"], generated),
        "metadata": metadata(title, props=[prop("assessment-kind", "self-assessment"), prop("app", meta["app"]),
                                           prop("environment", meta["env"]), prop("commit", meta["commit"]),
                                           prop("image", meta.get("image") or "")],
                             remarks="The information system owner's continuous self-assessment, generated by cicd-ref-arch "
                                     "from this commit's pipeline records. Not an official assessment."),
        "import-ap": {"href": meta.get("plan_href") or f"#{uid('ap-resource', meta['app'])}"},
        "results": [{
            "uuid": uid("result", meta["app"], meta["commit"], generated),
            "title": title, "description": f"{counts['satisfied']} of {len(summary_rows)} objectives satisfied; "
                                           + ", ".join(f"{v} {k}" for k, v in sorted(coverage.items())) + ".",
            "start": generated, "end": generated,
            "props": [prop("coverage-" + k, v) for k, v in sorted(coverage.items())],
            "reviewed-controls": {"control-selections": [{"include-controls": [{"control-id": c} for c in controls]}]},
            **({"observations": list(observations.values())} if observations else {}),
            "findings": findings}],
        "back-matter": {"resources": [{"uuid": uid("ap-resource", meta["app"]), "title": "Assessment plan",
                                       "description": "The evidence selectors of the merged layers are the plan: "
                                                      "see the component definitions of each layer.",
                                       "rlinks": [{"href": meta.get("compliance_url") or _instance().get("compliance_url", "")}]}]}}}
    summary = {"schema": "assessment-summary/v1", "kind": "self-assessment", "app": meta["app"], "env": meta["env"],
               "commit": meta["commit"], "image": meta.get("image"), "generated": generated,
               "counts": counts, "coverage": coverage, "objectives": summary_rows}
    return ar, summary


def cmd_assess(a) -> int:
    catalog = json.loads(Path(a.catalog).read_text())
    profile = json.loads(Path(a.profile).read_text())
    objs = objectives_for(catalog, profile_controls(profile))
    layers = [L for L in (load_layer(a.platform, "platform"), load_layer(a.app_layer, "app"),
                          load_layer(a.sysadmin_layer, "sysadmin")) if L]
    ev = Evidence(Path(a.evidence), Path(a.releases) if a.releases else None, a.app, commit=a.commit, image=a.image)
    rec = ev.record or {}
    meta = {"app": a.app, "env": a.env, "commit": a.commit or rec.get("commit") or "unknown",
            "image": a.image or rec.get("image")}
    ar, summary = assess(objs, merged(layers), ev, meta)
    summary["layers"] = [{"layer": L["layer"], "component": L.get("component"), "path": L["path"]} for L in layers]
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "assessment-results.json").write_text(json.dumps(ar, indent=1) + "\n")
    (out / "assessment-summary.json").write_text(json.dumps(summary, indent=1) + "\n")
    c, cov = summary["counts"], summary["coverage"]
    print(f"self-assessment: {c['satisfied']}/{len(objs)} objectives satisfied; " + ", ".join(f"{v} {k}" for k, v in sorted(cov.items())))
    for r in summary["objectives"]:
        if r["state"] != "satisfied":
            why = "; ".join(e["found"] for e in r["evidence"] if not e["holds"]) or r["reason"]
            print(f"  {r['id']:<15} {r['coverage']:<10} {why}")
    return 0


# ---------------------------------------------------------------- system security plan


def cmd_ssp(a) -> int:
    app = yaml.safe_load(Path(a.app_config).read_text())
    catalog = json.loads(Path(a.catalog).read_text())
    profile = json.loads(Path(a.profile).read_text())
    cids = profile_controls(profile)
    objs = objectives_for(catalog, cids)
    layers = [L for L in (load_layer(a.platform, "platform"), load_layer(a.app_layer, "app"),
                          load_layer(a.sysadmin_layer, "sysadmin")) if L]
    stmts = merged(layers)
    this = uid("this-system", app["name"])
    comps = [{"uuid": this, "type": "this-system", "title": app.get("title", app["name"]),
              "description": app.get("description", app["name"]), "status": {"state": "operational"}}]
    comp_uuid = {}
    for L in layers:
        comp_uuid[L["layer"]] = uid("component", L.get("component", L["layer"]))
        comps.append({"uuid": comp_uuid[L["layer"]], "type": L.get("type", "software"), "title": L.get("title", L.get("component", L["layer"])),
                      "description": (L.get("description") or L.get("title") or L["layer"]).strip(),
                      "props": [prop("layer", L["layer"])], "status": {"state": "operational"}})
    reqs = []
    for cid in cids:
        mine = [o for o in objs if o["control"] == cid]
        by_layer: dict[str, list[str]] = {}
        states = []
        for o in mine:
            st = stmts.get(o["id"])
            if st is None:
                states.append("planned")
                continue
            states.append("not-applicable" if st.get("not-applicable") else "implemented")
            by_layer.setdefault(st["layer"], []).append(f"{o['id']}: " + (st.get("statement") or f"not applicable: {st.get('not-applicable')}"))
        status = "implemented" if all(s in ("implemented", "not-applicable") for s in states) else (
            "partial" if any(s == "implemented" for s in states) else "planned")
        reqs.append({"uuid": uid("req", app["name"], cid), "control-id": cid,
                     "props": [{"name": "implementation-status", "value": status}],
                     **({"by-components": [{"component-uuid": comp_uuid[l], "uuid": uid("bc", app["name"], cid, l),
                                            "description": "\n".join(lines)} for l, lines in by_layer.items()]} if by_layer else {})})
    ssp = {"system-security-plan": {
        "uuid": uid("ssp", app["name"]),
        "metadata": metadata(f"System security plan: {app.get('title', app['name'])}",
                             props=[prop("app", app["name"]), prop("tenant", app.get("tenant", ""))],
                             remarks="Generated from the profile and the platform, app and sysadmin layers. "
                                     "Leveraged authorizations (a platform SSP) are a later step."),
        "import-profile": {"href": a.profile_href or a.profile},
        "system-characteristics": {
            "system-ids": [{"identifier-type": NS, "id": app["name"]}],
            "system-name": app.get("title", app["name"]),
            "description": app.get("description", app["name"]),
            "security-sensitivity-level": app.get("sensitivity", "low"),
            "system-information": {"information-types": [{
                "uuid": uid("it", app["name"]), "title": app.get("information", {}).get("title", "Application data"),
                "description": app.get("information", {}).get("description", "Data the application stores."),
                "confidentiality-impact": {"base": f"fips-199-{app.get('impact', 'low')}"},
                "integrity-impact": {"base": f"fips-199-{app.get('impact', 'low')}"},
                "availability-impact": {"base": f"fips-199-{app.get('impact', 'low')}"}}]},
            "security-impact-level": {"security-objective-confidentiality": f"fips-199-{app.get('impact', 'low')}",
                                      "security-objective-integrity": f"fips-199-{app.get('impact', 'low')}",
                                      "security-objective-availability": f"fips-199-{app.get('impact', 'low')}"},
            "status": {"state": "operational"},
            "authorization-boundary": {"description": app.get("boundary", "The application's environments on cicd-ref-arch.")}},
        "system-implementation": {
            "users": [{"uuid": uid("user", app["name"], "owner"), "title": "Information system owner",
                       "props": [{"name": "type", "value": "internal"}]}],
            "components": comps},
        "control-implementation": {"description": "Objective-level statements per layer; status from coverage.",
                                   "implemented-requirements": reqs}}}
    print(json.dumps(ssp, indent=1))
    return 0


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    e = sub.add_parser("excerpt")
    e.add_argument("--catalog", required=True)
    e.add_argument("--profile", required=True)
    e.add_argument("--source", required=True, help="where the full catalog came from (recorded)")
    e.add_argument("--out", required=True)
    c = sub.add_parser("component")
    c.add_argument("layer")
    c.add_argument("--kind", choices=LAYERS, default="platform")
    c.add_argument("--source", default="#", help="href of the profile or catalog the statements answer")
    for name in ("assess", "ssp"):
        s = sub.add_parser(name)
        s.add_argument("--catalog", required=True)
        s.add_argument("--profile", required=True)
        s.add_argument("--platform", required=True)
        s.add_argument("--app-layer")
        s.add_argument("--sysadmin-layer")
        if name == "assess":
            s.add_argument("--evidence", required=True, help="directory with security.json, sbom.cdx.json, ci-result-*.json, app.yaml")
            s.add_argument("--releases", help="releases/ of the compliance repo")
            s.add_argument("--app", required=True)
            s.add_argument("--env", required=True)
            s.add_argument("--commit")
            s.add_argument("--image")
            s.add_argument("--out", required=True)
        else:
            s.add_argument("--app-config", required=True, help="apps/<app>/app.yaml of the compliance repo")
            s.add_argument("--profile-href")
    a = ap.parse_args()
    sys.exit({"excerpt": cmd_excerpt, "component": cmd_component, "assess": cmd_assess, "ssp": cmd_ssp}[a.cmd](a))


if __name__ == "__main__":
    main()
