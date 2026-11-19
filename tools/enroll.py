#!/usr/bin/env python3
"""enroll: an admin puts an app repo onto the platform (docs/enroll.md).

  FORGEJO_TOKEN=<admin token for the app repo> CICD_BOT_USER=... CICD_BOT_TOKEN=... \\
    tools/enroll.py --tenant ffwf --repo ffwf/cicd-demo-app --app demo --cluster c-local --owner alice

1. writes tenants/<app>.yaml here (commit and push it: deploys of the app are refused until then)
2. sets the app repo's Actions variables CICD_BOT_USER, CICD_CLUSTER and secret CICD_BOT_TOKEN
3. commits templates/ci/app.yaml into the app repo as .forgejo/workflows/cicd.yaml

Run it again to update the workflow or rotate the token. Developers of the app need write access
to its code only; they never see the token, and don't need access to this repo.
Needs Python 3.10+ and PyYAML.
"""
from __future__ import annotations

import argparse
import base64
import datetime as dt
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
WORKFLOW = ".forgejo/workflows/cicd.yaml"


def api(method: str, url: str, token: str, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers={
        "Authorization": f"token {token}", "Accept": "application/json", "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            raw = r.read()
            return r.status, json.loads(raw) if raw else None
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(errors="replace")[:300]


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--repo", required=True, help="owner/name of the app repo on this forge")
    ap.add_argument("--app", required=True, help="the app's name (metadata.name in its cicd.yaml)")
    ap.add_argument("--path", default=".", help="where the app's cicd.yaml is in its repo")
    ap.add_argument("--cluster", action="append", required=True)
    ap.add_argument("--owner", action="append", default=[], help="people responsible for the app")
    ap.add_argument("--tenant", required=True, help="the tenant (team or organisation) the app belongs to")
    ap.add_argument("--branch", help="branch to commit the workflow to (default: the repo's default)")
    ap.add_argument("--server", default=os.environ.get("FORGEJO_URL", "https://forge.goblincorps.com"))
    a = ap.parse_args()

    token = os.environ.get("FORGEJO_TOKEN") or sys.exit("FORGEJO_TOKEN (admin on the app repo) is not set")
    bot_user = os.environ.get("CICD_BOT_USER") or sys.exit("CICD_BOT_USER is not set")
    bot_token = os.environ.get("CICD_BOT_TOKEN") or sys.exit("CICD_BOT_TOKEN is not set")
    base = f"{a.server.rstrip('/')}/api/v1/repos/{a.repo}"

    code, repo = api("GET", base, token)
    if code != 200:
        sys.exit(f"cannot read {a.repo}: {code} {repo}")
    if not repo.get("permissions", {}).get("admin"):
        sys.exit(f"the token is not an admin of {a.repo}: enrolling sets its secrets")

    # 1. the tenant record
    tenant = {"apiVersion": "cicd.ffwf.net/v1alpha1", "kind": "Tenant", "metadata": {"name": a.app},
              "spec": {"tenant": a.tenant, "repo": a.repo, "path": a.path, "clusters": a.cluster, "owners": a.owner,
                       "enrolled": dt.date.today().isoformat()}}
    path = ROOT / "tenants" / f"{a.app}.yaml"
    path.parent.mkdir(exist_ok=True)
    path.write_text("# Enrolled by an admin with tools/enroll.py (docs/enroll.md).\n"
                    + yaml.safe_dump(tenant, sort_keys=False))
    print(f"wrote {path.relative_to(ROOT)}: commit and push it")

    # 2. what the pipeline needs on the app repo
    code, out = api("PUT", f"{base}/actions/secrets/CICD_BOT_TOKEN", token, {"data": bot_token})
    print(f"secret CICD_BOT_TOKEN: {code}")
    if code not in (201, 204):
        sys.exit(out)
    for name, value in (("CICD_BOT_USER", bot_user), ("CICD_CLUSTER", a.cluster[0])):
        code, out = api("POST", f"{base}/actions/variables/{name}", token, {"value": value})
        if code not in (201, 204):
            code, out = api("PUT", f"{base}/actions/variables/{name}", token, {"value": value})
        print(f"variable {name}={value}: {code}")
        if code not in (201, 204):
            sys.exit(out)

    # 3. the pipeline itself
    text = (ROOT / "templates" / "ci" / "app.yaml").read_text().replace("  APP: .  ", f"  APP: {a.path}  ", 1)
    branch = a.branch or repo.get("default_branch") or "main"
    code, cur = api("GET", f"{base}/contents/{WORKFLOW}?ref={branch}", token)
    body = {"content": base64.b64encode(text.encode()).decode(), "branch": branch,
            "message": f"cicd: enroll on {', '.join(a.cluster)} (platform pipeline from {a.server}/ffwf/cicd-ref-arch)",
            "author": {"name": "cicd-bot", "email": "cicd-bot@noreply.invalid"},
            "committer": {"name": "cicd-bot", "email": "cicd-bot@noreply.invalid"}}
    if code == 200:
        if base64.b64decode(cur["content"]).decode() == text:
            print(f"{WORKFLOW}: unchanged")
            return
        code, out = api("PUT", f"{base}/contents/{WORKFLOW}", token, dict(body, sha=cur["sha"]))
    else:
        code, out = api("POST", f"{base}/contents/{WORKFLOW}", token, body)
    print(f"{WORKFLOW} on {branch}: {code}")
    if code not in (200, 201):
        sys.exit(out)


if __name__ == "__main__":
    main()
