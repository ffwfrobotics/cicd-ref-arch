#!/usr/bin/env python3
"""Scan evidence as releases on CI/CD's evidence repo, not files in this repo (docs/evidence.md).

An environment's evidence/ keeps only small files here: evidence.json (which release holds the rest:
each file's name, sha256 and size), the self-assessment summary and the approval record. The scans
themselves (SBOMs, scanner output, the security record, the OSCAL assessment) are the assets of one
release on the evidence repo, tag <cluster>/<app>/<env>/<content digest>. Same files, same tag: a
retried job or an unchanged re-assessment reuses the release it already made.

Only the pipeline writes there, and only to CI/CD's repos (never to an app's repo). Who can read the
scans is who can read the evidence repo. Where and how long (cicd-cluster.yaml `evidence`; a tenant's
`spec.evidence` overrides any key, and turns it on for that app alone if the cluster names no repo): keep: N versions per environment (default 1, "latest only") and/or
days: D; a version still named by an environment or a pending promotion is always kept.

  evidence.py publish  DIR --cluster C --app A --env E     upload DIR's scans, write DIR/evidence.json
  evidence.py fetch    DIR [--name sbom.cdx.json ...]       download (and verify) what DIR/evidence.json lists
  evidence.py prune    --cluster C [--root .]               apply retention to every environment
  evidence.py backfill --cluster C [--root .]               move inline evidence of envs/ and promotions/ out

FORGEJO_TOKEN is the bot's token; the server is FORGEJO_SERVER or GITHUB_SERVER_URL."""
import argparse
import datetime as dt
import hashlib
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path

import yaml

SCHEMA = "evidence/v1"
MANIFEST = "evidence.json"
# small, read on every page and by the promotion request: they stay in the platform repo
INLINE = {MANIFEST, "assessment-summary.json", "approval.json"}


def now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_yaml(p: Path) -> dict:
    return (yaml.safe_load(p.read_text()) or {}) if p.exists() else {}


# ---------------------------------------------------------------- configuration


def policy(root: Path, cluster: str, app: str | None = None) -> dict | None:
    """The evidence settings for an app on a cluster: {repo, keep, days}, or None (evidence stays inline).
    cicd-cluster.yaml `evidence` is the default; tenants/<app>.yaml `spec.evidence` overrides any key."""
    base = load_yaml(root / "clusters" / cluster / "cicd-cluster.yaml").get("evidence") or {}
    out = {"repo": base.get("repo"), "keep": base.get("keep", 1), "days": base.get("days")}
    if app:     # a tenant may name a repo of its own (or the only one, while the cluster has none)
        t = load_yaml(root / "tenants" / f"{app}.yaml")
        out.update({k: v for k, v in ((t.get("spec") or {}).get("evidence") or {}).items() if k in ("repo", "keep", "days")})
    return out if out["repo"] else None


def server() -> str:
    return (os.environ.get("FORGEJO_SERVER") or os.environ.get("GITHUB_SERVER_URL") or "").rstrip("/")


def active(root: Path, cluster: str, app: str | None = None) -> dict | None:
    """The policy if evidence goes to releases here and now: configured, with a token and a server."""
    p = policy(root, cluster, app)
    if p is None:
        return None
    if not os.environ.get("FORGEJO_TOKEN") or not server():
        print(f"::warning::evidence kept inline: {p['repo']} is configured but FORGEJO_TOKEN or the server is not set",
              file=sys.stderr)
        return None
    return p


# ---------------------------------------------------------------- the forge


class Forge:
    """Releases and their assets on the forge, with the bot's token."""

    def __init__(self, base: str | None = None, token: str | None = None):
        self.base = (base or server()).rstrip("/")
        self.token = token or os.environ["FORGEJO_TOKEN"]

    def _req(self, method: str, url: str, data: bytes | None = None, ctype: str | None = None):
        h = {"Authorization": f"token {self.token}", "Accept": "application/json"}
        if ctype:
            h["Content-Type"] = ctype
        req = urllib.request.Request(url, data=data, method=method, headers=h)
        try:
            with urllib.request.urlopen(req, timeout=120) as r:
                return r.status, r.read()
        except urllib.error.HTTPError as e:
            return e.code, e.read()

    def api(self, method: str, path: str, body: dict | None = None):
        code, raw = self._req(method, f"{self.base}/api/v1{path}",
                              json.dumps(body).encode() if body is not None else None,
                              "application/json" if body is not None else None)
        try:
            return code, json.loads(raw) if raw else None
        except json.JSONDecodeError:
            return code, raw.decode(errors="replace")

    def release(self, repo: str, tag: str) -> dict | None:
        code, rel = self.api("GET", f"/repos/{repo}/releases/tags/{urllib.parse.quote(tag, safe='')}")
        return rel if code == 200 else None

    def create_release(self, repo: str, tag: str, body: str) -> dict:
        code, info = self.api("GET", f"/repos/{repo}")
        if code != 200:
            raise RuntimeError(f"evidence repo {repo}: {code} {info}")
        code, rel = self.api("POST", f"/repos/{repo}/releases", {
            "tag_name": tag, "target_commitish": info["default_branch"], "name": tag, "body": body})
        if code != 201:
            raise RuntimeError(f"creating release {tag} on {repo}: {code} {rel}")
        return rel

    def upload(self, repo: str, release_id: int, name: str, data: bytes) -> dict:
        boundary = uuid.uuid4().hex
        body = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"attachment\"; filename=\"{name}\"\r\n"
                f"Content-Type: application/octet-stream\r\n\r\n").encode() + data + f"\r\n--{boundary}--\r\n".encode()
        code, raw = self._req("POST", f"{self.base}/api/v1/repos/{repo}/releases/{release_id}/assets?name={urllib.parse.quote(name)}",
                              body, f"multipart/form-data; boundary={boundary}")
        if code != 201:
            raise RuntimeError(f"uploading {name} to {repo} release {release_id}: {code} {raw[:200]!r}")
        return json.loads(raw)

    def download(self, url: str) -> bytes:
        code, raw = self._req("GET", url)
        if code != 200:
            raise RuntimeError(f"downloading {url}: {code}")
        return raw

    def releases(self, repo: str) -> list[dict]:
        out, page = [], 1
        while True:
            code, rels = self.api("GET", f"/repos/{repo}/releases?limit=50&page={page}")
            if code != 200 or not rels:
                return out
            out += rels
            page += 1

    def delete(self, repo: str, tag: str):
        q = urllib.parse.quote(tag, safe="")
        self.api("DELETE", f"/repos/{repo}/releases/tags/{q}")
        self.api("DELETE", f"/repos/{repo}/tags/{q}")     # the release goes, its tag doesn't by itself


# ---------------------------------------------------------------- one environment's evidence


def read_manifest(d: Path) -> dict | None:
    p = d / MANIFEST
    return json.loads(p.read_text()) if p.exists() else None


def scans_in(d: Path) -> dict[str, bytes]:
    """The files of an evidence directory that go to the release: everything but the inline ones."""
    return {p.name: p.read_bytes() for p in sorted(d.iterdir()) if p.is_file() and p.name not in INLINE} if d.is_dir() else {}


def fetch(d: Path, forge: Forge, names: list[str] | None = None) -> list[str]:
    """Download what evidence.json lists (or just `names`) into d, each checked against its sha256."""
    m = read_manifest(d)
    if not m or not m.get("tag"):
        return []
    got = []
    for name, f in m["files"].items():
        if (names and name not in names) or (d / name).exists():
            continue
        data = forge.download(f["url"])
        if sha256(data) != f["sha256"]:
            raise RuntimeError(f"{m['repo']} {m['tag']}/{name}: sha256 differs from {MANIFEST}: altered")
        (d / name).write_bytes(data)
        got.append(name)
    return got


def tag_for(cluster: str, app: str, env: str, files: dict[str, bytes]) -> str:
    digest = sha256("".join(f"{n}:{sha256(b)}\n" for n, b in sorted(files.items())).encode())[:16]
    return f"{cluster}/{app}/{env}/{digest}"


def publish(d: Path, cluster: str, app: str, env: str, pol: dict, forge: Forge, meta: dict | None = None) -> dict | None:
    """Upload d's scans as one release and replace them with d/evidence.json. Files the previous
    version listed but d lacks are carried over (fetched), so every version is complete on its own."""
    if read_manifest(d):
        fetch(d, forge)
    files = scans_in(d)
    if not files:
        return read_manifest(d)
    repo, tag = pol["repo"], tag_for(cluster, app, env, files)
    rel = forge.release(repo, tag)
    have = {a["name"]: a for a in (rel or {}).get("assets") or []}
    if rel is None:
        rel = forge.create_release(repo, tag, "\n".join(
            [f"Evidence of {app} {env} on {cluster}, kept by the CI/CD pipeline."]
            + [f"- {k}: {v}" for k, v in (meta or {}).items() if v]))
    for name, data in files.items():
        if name not in have or have[name].get("size") != len(data):
            have[name] = forge.upload(repo, rel["id"], name, data)
    manifest = {"schema": SCHEMA, "repo": repo, "tag": tag, "release": rel.get("html_url") or f"{forge.base}/{repo}/releases/tag/{tag}",
                "created": rel.get("created_at") or now(), **({"meta": meta} if meta else {}),
                "files": {n: {"sha256": sha256(b), "bytes": len(b), "url": have[n]["browser_download_url"]}
                          for n, b in files.items()}}
    (d / MANIFEST).write_text(json.dumps(manifest, indent=1) + "\n")
    for name in files:
        (d / name).unlink()
    return manifest


# ---------------------------------------------------------------- retention


def referenced(root: Path) -> set[str]:
    """Tags still named by an environment or a pending promotion: never pruned."""
    out = set()
    for p in list(root.glob("envs/*/*/*/evidence/" + MANIFEST)) + list(root.glob("promotions/pending/*/evidence/" + MANIFEST)):
        try:
            t = json.loads(p.read_text()).get("tag")
        except json.JSONDecodeError:
            continue
        if t:
            out.add(t)
    return out


def doomed(releases: list[dict], keep_refs: set[str], live: set[tuple[str, str, str]],
           pol_of, now_t: dt.datetime) -> list[str]:
    """Which release tags retention removes. Per environment: the newest `keep` (if it still exists), those
    younger than `days`, and every referenced one stay. An environment that's gone keeps only `days`."""
    groups: dict[tuple[str, str, str], list[dict]] = {}
    for r in releases:
        parts = r["tag_name"].split("/")
        if len(parts) == 4:
            groups.setdefault(tuple(parts[:3]), []).append(r)
    out = []
    for (cluster, app, env), rels in groups.items():
        pol = pol_of(cluster, app)
        if pol is None:
            continue
        rels.sort(key=lambda r: r.get("created_at") or "", reverse=True)
        keep_n = int(pol.get("keep") or 0) if (cluster, app, env) in live else 0
        days = pol.get("days")
        for i, r in enumerate(rels):
            t = r["tag_name"]
            if t in keep_refs or i < keep_n:
                continue
            if days is not None:
                made = dt.datetime.fromisoformat((r.get("created_at") or "").replace("Z", "+00:00"))
                if now_t - made < dt.timedelta(days=float(days)):
                    continue
            out.append(t)
    return out


def prune(root: Path, cluster: str, forge: Forge) -> list[str]:
    base = policy(root, cluster)
    repos = ({base["repo"]} if base else set()) | {p["repo"] for a in [t.stem for t in (root / "tenants").glob("*.yaml")]
                                                   if (p := policy(root, cluster, a))}
    live = {(cluster, m.parent.parent.name, m.parent.name) for m in root.glob(f"envs/{cluster}/*/*/cicd-env.yaml")}
    refs = referenced(root)
    gone = []
    for repo in sorted(repos):
        rels = [r for r in forge.releases(repo) if r["tag_name"].startswith(cluster + "/")]
        for t in doomed(rels, refs, live, lambda c, a: (p if (p := policy(root, c, a)) and p["repo"] == repo else None),
                        dt.datetime.now(dt.timezone.utc)):
            forge.delete(repo, t)
            gone.append(f"{repo} {t}")
    return gone


# ---------------------------------------------------------------- moving what's inline today


def backfill(root: Path, cluster: str, forge: Forge, git_commit: str | None = None) -> list[str]:
    """Every environment's (and pending promotion's) inline evidence becomes a release. Applied promotions
    keep checksums only: their files stay in this repo's history at `git_commit`."""
    done = []
    for ev in sorted(root.glob(f"envs/{cluster}/*/*/evidence")):
        app, env = ev.parent.parent.name, ev.parent.name
        pol = policy(root, cluster, app)
        if pol and scans_in(ev):
            m = publish(ev, cluster, app, env, pol, forge, {"backfilled": now()})
            done.append(f"{ev.relative_to(root)} -> {m['tag']}")
    for ev in sorted(root.glob("promotions/pending/*/evidence")):
        promo = load_yaml(ev.parent / "promotion.yaml")
        if promo.get("cluster") != cluster or not scans_in(ev):
            continue
        pol = policy(root, cluster, promo["app"])
        if pol:
            m = publish(ev, cluster, promo["app"], f"promotion-{promo['id']}", pol, forge, {"backfilled": now()})
            done.append(f"{ev.relative_to(root)} -> {m['tag']}")
    for ev in sorted(root.glob("promotions/done/*/evidence")):
        promo = load_yaml(ev.parent / "promotion.yaml")
        files = scans_in(ev)
        if promo.get("cluster") != cluster or not files or not policy(root, cluster, promo["app"]):
            continue
        (ev / MANIFEST).write_text(json.dumps({
            "schema": SCHEMA, "repo": None, "tag": None, "created": now(),
            "kept": f"in this repo's history at {git_commit}" if git_commit else "in this repo's history",
            "files": {n: {"sha256": sha256(b), "bytes": len(b)} for n, b in files.items()}}, indent=1) + "\n")
        for n in files:
            (ev / n).unlink()
        done.append(f"{ev.relative_to(root)}: checksums only")
    return done


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--root", default=".")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("publish")
    p.add_argument("dir")
    for k in ("--cluster", "--app", "--env"):
        p.add_argument(k, required=True)
    f = sub.add_parser("fetch")
    f.add_argument("dir")
    f.add_argument("--name", action="append")
    for name in ("prune", "backfill"):
        s = sub.add_parser(name)
        s.add_argument("--cluster", required=True)
        s.add_argument("--git-commit")
    a = ap.parse_args()
    root = Path(a.root)
    if a.cmd == "fetch":
        print("\n".join(fetch(Path(a.dir), Forge(), a.name)))
        return
    if not os.environ.get("FORGEJO_TOKEN") or not server():
        sys.exit("FORGEJO_TOKEN and FORGEJO_SERVER (or GITHUB_SERVER_URL) are needed")
    if a.cmd == "publish":
        pol = active(root, a.cluster, a.app)
        if pol is None:
            sys.exit(f"no evidence repo for {a.app} on {a.cluster} (cicd-cluster.yaml or the tenant's spec.evidence)")
        m = publish(Path(a.dir), a.cluster, a.app, a.env, pol, Forge())
        print(m["tag"] if m else "nothing to publish")
    elif a.cmd == "prune":
        print("\n".join(prune(root, a.cluster, Forge())) or "nothing to prune")
    elif a.cmd == "backfill":
        print("\n".join(backfill(root, a.cluster, Forge(), a.git_commit)) or "nothing inline")


if __name__ == "__main__":
    main()
