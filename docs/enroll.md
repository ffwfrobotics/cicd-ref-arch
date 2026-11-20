# Enrolling an app

The platform is the product; an app's developers use it without access to it. An admin enrolls each app once. After that, the developers push code and nothing else. **The pipeline runs in the platform repo** (`.forgejo/workflows/pipeline.yaml`), and the app repo holds no workflow and no token.

| The app's developers | The platform admin |
|---|---|
| Code, tests, `Dockerfile`, `deploy/` | Enrolls the app: `tenants/<app>.yaml` and a push webhook on the app repo |
| `cicd.yaml`: test command, URL patterns, idle time | The platform repo, its pipeline and its bot token |
| `security/`: suppressions, stricter settings | |
| Requests a promotion | Approves promotions (someone other than the requester) |

Example: [ffwf/cicd-demo-app](https://forge.goblincorps.com/ffwf/cicd-demo-app).

## How a push reaches the pipeline

```
push to app repo ──webhook──▶ cicd-dashboard /hooks/forge ──dispatch──▶ cicd-ref-arch pipeline.yaml
                 (signed)                                  (app, branch, sha, who pushed)
     every 5 min: environments workflow, `cicd.py dispatch-missing` ──▶ the same, for any push missed
```

- A dispatch names the **enrolled app**, not a repo: the pipeline reads `tenants/<app>.yaml` to know which repo and path to check out. Nobody can point it at a repo that wasn't enrolled.
- Only the platform repo's writers (the admins and the bot) can dispatch it. The dashboard does so with the platform token, after checking the signature (webhooks) or the user's write access on the app repo (self-service).
- Each run in the platform repo is titled `pipeline`; its inputs (`app`, `branch`, `sha`, `action`, `actor`) say what it is for, and the dashboard reads them to show each app commit's jobs.
- Without the webhook (or if the dashboard is down), pushes still start the pipeline within 5 minutes.

## 1. The app meets the contract

See `templates/app/` and [contract.md](contract.md):
- `cicd.yaml` at the path you enroll;
- a kustomize base in `deploy/` whose image is the literal name `app-image`;
- a Dockerfile with its base pinned by digest;
- a `/healthz` readiness probe;
- `security/policy.yaml` and `security/vex.openvex.json`, which can start empty.

## 2. Enroll

From a checkout of this repo, with a token that is an admin of the app repo, and the dashboard's webhook secret (the `hook-secret` in its `dashboard-platform` Secret):

```sh
FORGEJO_TOKEN=<admin token> CICD_HOOK_SECRET=<webhook secret> \
  python3 tools/enroll.py --tenant ffwf --repo ffwf/cicd-demo-app --app demo --cluster c-local --owner alice \
    --hook-url https://dashboard.c-local.k.ffwf.net/hooks/forge
git add tenants/demo.yaml && git commit -m "enroll demo" && git push
```

It:
1. writes `tenants/<app>.yaml`. The pipeline refuses an app until this is pushed, and only checks out the enrolled repo;
2. adds (or updates) a push webhook on the app repo, to the dashboard;
3. removes what the old model kept in the app repo, if it's there: `.forgejo/workflows/cicd.yaml`, the secret `CICD_BOT_TOKEN`, the variables `CICD_BOT_USER` and `CICD_CLUSTER`. Removing the workflow is a commit, and that push is the first platform run.

Run it again to update the webhook.

## 3. What the developers then get

- **Push to the dev branch** (`environments.dev.branch` in `cicd.yaml`): live at `<app>-dev.<cluster>.<zone>`.
- **Any other branch:** live at `<app>-<branch>.<cluster>.<zone>`. Deleting the branch removes it within a minute: the app's pipeline asks the `environments` workflow here to clean up.
- **Every run:** a test record and a security record, shown in the run's summary. Dev and branch deploys go ahead on findings; a secret stops them.
- **Prod:** `request-promotion` in this repo, approved by someone else. See [promotion.md](promotion.md) and [security.md](security.md).

## Self-service

After enrollment, anyone with **write on the app repo** helps themselves, from `cicd-dashboard`, signed in through the forge.

The dashboard checks that you have write on the app repo, then dispatches the platform pipeline with the action and your login, which the pipeline records:

| Action | Effect |
|---|---|
| `pause` (branch) | The branch's environment is removed. Its pushes skip CI/CD until it is resumed. Recorded in `envs/<cluster>/<app>/paused.yaml`. |
| `resume` (branch) | Its next push goes through CI/CD again. |
| `remove-env` (branch) | Removes the environment now. The next push brings it back. |
| `request-promotion` | Opens the promotion PR, with you as the requester. Someone else approves it. |

**Tenant limit.** At most **16 branch environments per tenant** are in CI/CD at once (`tenants/_limits.yaml`).
- A push to a branch with no environment, while the tenant is at its limit, is routed out: no tests, no build, no deploy. The run says why, and the branch waits for a free slot.
- The dev branch, and branches that already have an environment, always go through.
- Branches themselves are unlimited.
- The limit is checked when a push is routed, so pushes that arrive together can briefly exceed it.

## Secrets at push

The forge-side hook `forge/pre-receive-gitleaks` refuses pushes that add a secret. It is an instance change, made by the forge admin on the forge host (or inside the Forgejo container), as the user that owns the repositories:
1. put `gitleaks` (the version and sha256 in `actions/setup/tools.txt`) where the Forgejo process can run it;
2. run `forge/install-pre-receive.sh <repositories root> <gitleaks path>`. The repositories root is `[repository] ROOT` in `app.ini`. The script installs the hook into `hooks/pre-receive.d/` of this repo and of every repo in `tenants/`. Run it again after enrolling an app. On forge.goblincorps.com it is installed (2026-11-20, gitleaks at `/data/git/bin/gitleaks` in the forge container): ask the goblincorps hosting session to re-run it.

Don't use Forgejo's per-repo git-hook editor (`DISABLE_GIT_HOOKS = false`) for this: it lets every repo admin run code on the forge.

## Limits

- **The dashboard holds the platform token** (it dispatches the pipeline). Anyone who controls the dashboard's dev or prod deployment can start pipeline runs for enrolled apps, but only for enrolled repos and commits that exist in them.
- **Enrollment names a repo, not people.** Who may push code is the app repo's own access control.
- **Webhooks need the forge to reach the dashboard.** If it can't, the 5-minute safety net still runs every push.
