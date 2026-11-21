#!/usr/bin/env python3
"""enroll: an admin puts an app repo onto the platform (docs/enroll.md).

  FORGEJO_TOKEN=<admin token for the app repo> CICD_HOOK_SECRET=<the dashboard's webhook secret> \
    tools/enroll.py --tenant ffwf --repo ffwf/cicd-demo-app --app demo --cluster c-local --owner alice \
      --hook-url https://dashboard.c-local.k.ffwf.net/hooks/forge

1. writes tenants/<app>.yaml here (commit and push it: the pipeline refuses unenrolled apps)
2. adds a push webhook to the app repo: the dashboard turns each push into a run of this repo's
   pipeline (.forgejo/workflows/pipeline.yaml). Without the webhook, the environments workflow
   still starts it within 5 minutes.
3. removes what the app repo held under the old model, if anything: the workflow
   .forgejo/workflows/cicd.yaml, the secret CICD_BOT_TOKEN, the variables CICD_BOT_USER and
   CICD_CLUSTER. The app repo then holds no pipeline and no token.

Run it again to update the webhook. Developers of the app need write access to its code only.
Needs Python 3.10+ and PyYAML.
"""
from __future__ import annotations

import argparse
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
    ap.add_argument("--branch", help="branch an old-model workflow is removed from (default: the repo's default)")
    ap.add_argument("--hook-url", default=os.environ.get("CICD_HOOK_URL", ""),
                    help="the dashboard's webhook endpoint, https://<dashboard>/hooks/forge")
    ap.add_argument("--server", default=os.environ.get("FORGEJO_URL", "https://forge.goblincorps.com"))
    a = ap.parse_args()

    token = os.environ.get("FORGEJO_TOKEN") or sys.exit("FORGEJO_TOKEN (admin on the app repo) is not set")
    hook_secret = os.environ.get("CICD_HOOK_SECRET", "")
    if a.hook_url and not hook_secret:
        sys.exit("CICD_HOOK_SECRET (the dashboard's webhook secret) is not set")
    base = f"{a.server.rstrip('/')}/api/v1/repos/{a.repo}"

    code, repo = api("GET", base, token)
    if code != 200:
        sys.exit(f"cannot read {a.repo}: {code} {repo}")
    if not repo.get("permissions", {}).get("admin"):
        sys.exit(f"the token is not an admin of {a.repo}: enrolling adds its webhook")

    # 1. the tenant record
    tenant = {"apiVersion": "cicd.ffwf.net/v1alpha1", "kind": "Tenant", "metadata": {"name": a.app},
              "spec": {"tenant": a.tenant, "repo": a.repo, "path": a.path, "clusters": a.cluster, "owners": a.owner,
                       "enrolled": dt.date.today().isoformat()}}
    path = ROOT / "tenants" / f"{a.app}.yaml"
    path.parent.mkdir(exist_ok=True)
    if path.exists():   # re-enrolling keeps the original date
        tenant["spec"]["enrolled"] = (yaml.safe_load(path.read_text()) or {}).get("spec", {}).get("enrolled", tenant["spec"]["enrolled"])
    path.write_text("# Enrolled by an admin with tools/enroll.py (docs/enroll.md).\n"
                    + yaml.safe_dump(tenant, sort_keys=False))
    print(f"wrote {path.relative_to(ROOT)}: commit and push it")

    # 2. the push webhook
    if a.hook_url:
        hook = {"type": "forgejo", "active": True, "events": ["push", "delete"], "branch_filter": "*",
                "config": {"url": a.hook_url, "content_type": "json", "secret": hook_secret}}
        code, hooks = api("GET", f"{base}/hooks", token)
        same = [h for h in (hooks if code == 200 else []) if (h.get("config") or {}).get("url") == a.hook_url]
        if same:
            code, out = api("PATCH", f"{base}/hooks/{same[0]['id']}", token,
                            {"active": True, "events": hook["events"], "branch_filter": "*", "config": hook["config"]})
        else:
            code, out = api("POST", f"{base}/hooks", token, hook)
        print(f"webhook {a.hook_url}: {code}")
        if code not in (200, 201):
            sys.exit(out)
    else:
        print("no --hook-url: pushes start the pipeline within 5 minutes (environments workflow)")

    # 3. what the old model kept in the app repo
    branch = a.branch or repo.get("default_branch") or "main"
    code, cur = api("GET", f"{base}/contents/{WORKFLOW}?ref={branch}", token)
    if code == 200:
        code, out = api("DELETE", f"{base}/contents/{WORKFLOW}", token, {
            "sha": cur["sha"], "branch": branch,
            "message": f"cicd: the pipeline now runs in the platform ({a.server}/ffwf/cicd-ref-arch), not here",
            "author": {"name": "cicd-bot", "email": "cicd-bot@noreply.invalid"},
            "committer": {"name": "cicd-bot", "email": "cicd-bot@noreply.invalid"}})
        print(f"removed {WORKFLOW} on {branch}: {code}")
        if code not in (200, 204):
            sys.exit(out)
    code, _ = api("DELETE", f"{base}/actions/secrets/CICD_BOT_TOKEN", token)
    print(f"secret CICD_BOT_TOKEN: {'removed' if code in (200, 204) else 'none'}")
    for name in ("CICD_BOT_USER", "CICD_CLUSTER"):
        code, _ = api("DELETE", f"{base}/actions/variables/{name}", token)
        print(f"variable {name}: {'removed' if code in (200, 204) else 'none'}")


if __name__ == "__main__":
    main()
