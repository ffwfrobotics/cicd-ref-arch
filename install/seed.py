#!/usr/bin/env python3
"""Seed a lab forge: users, orgs, teams, bot tokens and OAuth apps, from instances/<name>.seed.yaml.
Idempotent: what exists is left alone (a token or OAuth secret is only shown when made, and kept in
the secrets directory then).

  seed.py instances/<name>.env [--api http://127.0.0.1:13000]   (SECRETS as for bootstrap.sh)
"""
import argparse, os, secrets as rnd, sys
from pathlib import Path
import httpx, yaml

ap = argparse.ArgumentParser()
ap.add_argument("env")
ap.add_argument("--api", default="http://127.0.0.1:13000", help="the forge's root URL from here")
a = ap.parse_args()
env = dict(l.split("=", 1) for l in Path(a.env).read_text().splitlines() if "=" in l and not l.startswith("#"))
seed = yaml.safe_load(Path(a.env).with_suffix(".seed.yaml").read_text())
S = Path(os.environ.get("SECRETS") or f"/var/lib/lab/{env['CLUSTER']}/secrets")
admin = env["ADMIN_USER"]
c = httpx.Client(base_url=a.api.rstrip("/") + "/api/v1", auth=(admin, (S / "forgejo-admin").read_text().strip()), timeout=30)


def keep(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.write_text(value + "\n"); path.chmod(0o600)


def ok(r, *codes):
    if r.status_code not in codes:
        sys.exit(f"{r.request.method} {r.request.url.path}: {r.status_code} {r.text[:200]}")
    return r


zone = env["ZONE"]
for name, u in seed["users"].items():
    if c.get(f"/users/{name}").status_code == 200:
        print(f"user {name}: exists"); continue
    pw = rnd.token_urlsafe(18); keep(S / "users" / name, pw)
    ok(c.post("/admin/users", json={"username": name, "email": f"{name}@{zone}", "full_name": u.get("full_name", ""),
                                    "password": pw, "must_change_password": False, "visibility": "public"}), 201)
    print(f"user {name}: made (password in {S / 'users' / name})")

for org, o in seed["orgs"].items():
    if c.get(f"/orgs/{org}").status_code != 200:
        ok(c.post("/orgs", json={"username": org, "visibility": "private", "repo_admin_change_team_access": False}), 201)
        print(f"org {org}: made")
    have = {t["name"]: t for t in ok(c.get(f"/orgs/{org}/teams"), 200).json()}
    for team, t in (o.get("teams") or {}).items():
        units = ["repo.code", "repo.issues", "repo.pulls", "repo.releases", "repo.wiki", "repo.actions", "repo.packages"]
        body = {"name": team, "permission": t["permission"], "includes_all_repositories": bool(t.get("all_repos")),
                "units": units, "can_create_org_repo": t["permission"] == "write" and bool(t.get("all_repos"))}
        tid = have[team]["id"] if team in have else ok(c.post(f"/orgs/{org}/teams", json=body), 201).json()["id"]
        for m in t.get("members", []):
            ok(c.put(f"/teams/{tid}/members/{m}"), 204)
        for r in t.get("repos", []):
            if c.get(f"/repos/{org}/{r}").status_code == 200:
                ok(c.put(f"/teams/{tid}/repos/{org}/{r}"), 204)
        print(f"team {org}/{team}: {t['permission']}, {', '.join(t.get('members', []))}")

for user, scopes in (seed.get("tokens") or {}).items():
    f = S / "tokens" / user
    if f.exists():
        print(f"token {user}: kept"); continue
    pw = (S / "users" / user).read_text().strip()
    r = ok(httpx.post(f"{a.api.rstrip('/')}/api/v1/users/{user}/tokens", auth=(user, pw), timeout=30,
                      json={"name": "platform", "scopes": scopes}), 201)
    keep(f, r.json()["sha1"]); print(f"token {user}: made ({f})")

for app, uris in (seed.get("oauth_apps") or {}).items():
    f = S / "oauth" / app
    if f.exists():
        print(f"oauth app {app}: kept"); continue
    r = ok(c.post("/user/applications/oauth2", json={"name": app, "redirect_uris": uris, "confidential_client": True}), 201).json()
    keep(f, f"OAUTH_CLIENT_ID={r['client_id']}\nOAUTH_CLIENT_SECRET={r['client_secret']}")
    print(f"oauth app {app}: made ({f})")
