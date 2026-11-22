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

## From the dashboard: Add app

Any signed-in user can add an app; an admin approves it. In cicd-dashboard, **Add app**, then paste a clone URL:

| Source | What happens |
|---|---|
| A repo on another forge (GitHub, GitLab, another Forgejo) | Imported into this forge under the owner you pick, once, or as a pull **mirror** that keeps syncing. A private source needs a read token there. |
| A repo already on this forge | Used as it is (you need admin on it). |
| Empty | A new empty repo: push to it. |

The dashboard then, in this order (`cicd-dashboard/dashboard/enroll.py`):
1. **as you:** imports or creates the repo, gives the platform bot **read** on it (to check it out; CI/CD never writes to it, docs/enrollment.md "Who writes where"), and adds the push webhook;
2. **as the platform:** writes `tenants/<app>.yaml` with `status: pending` and `requestedBy: <you>`, and starts the first run.

**Pending** apps get the whole pipeline (contract check, tests, build, scans, self-assessment), but deploy **only to branch environments**: the default branch too, at `<app>-<branch>.<cluster>.<zone>`. There is no dev host and no promotion, and they count toward the tenant's branch limit.

**Approve** (on the app's page, for writers of this repo) is a commit to `tenants/<app>.yaml` in the approver's name: `status: approved`, `approved: {by, at}`. The default branch then deploys to dev, and the dev deploy removes the stand-in branch environment.

Developers keep working in one of three ways: push to the repo here (change the remote), push-mirror from their forge to here (Forgejo, GitHub and GitLab can all do this), or a push job in their own CI. An imported **mirror** syncs on the forge's mirror interval.

## 1. The app meets the contract

The pipeline's first step (`intake`) checks every push against [contract.md](contract.md) and posts what it found as commit statuses on the app repo. A missing `cicd.yaml` or `deploy/` base is filled in with defaults for the run (printed in the log, to commit); a missing Dockerfile stops the run with "nothing to run". So a repo with only a Dockerfile deploys. To start from a complete app, see `templates/app/` and [contract.md](contract.md):
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
- **Every deploy:** a runtime check: running, or what went wrong (crash with its last log lines, image pull, not ready, …). See [Runtime check](#runtime-check).
- **Prod:** `request-promotion` in this repo, approved by someone else. See [promotion.md](promotion.md) and [security.md](security.md).

## Runtime check

After each deploy, the `runtime` job (`tools/runtime.py`) watches the environment and posts one word
as the commit status `cicd/runtime`. The words, and what to do about each, are in
[contract.md](contract.md#after-the-deploy-the-runtime-check). A run whose app doesn't run is red.

It reads the cluster as `cicd-runtime/reader` (`platform/runtime`): pods, events, logs and
workloads, and only in environment namespaces, each of which binds the role in its `platform.yaml`.
That binding arrives with an environment's next deploy.

Setup, once per cluster, as a cluster admin:
1. Flux creates the ServiceAccount and its token Secret (`cicd-runtime/reader-token`).
2. Make a kubeconfig with server `https://kubernetes.default.svc`, the Secret's `ca.crt` and
   `token`, and store it as the platform repo's Actions secret `CICD_RUNTIME_KUBECONFIG`.
   The runner pods mount no token: only this repo's workflows get it.
3. Let the runners reach the API server (the kube service IP on 443, and the apiserver behind it).

Without the secret, the job says the check isn't configured and passes. To rotate, delete the
token Secret (Flux recreates it and Kubernetes issues a new token), then redo step 2.

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
- **The platform bot has write on every enrolled repo**: to check out private repos and post the contract statuses. It never pushes to them.
- **Apps added from the dashboard have no forge-side secret hook** until the forge admin re-runs `forge/install-pre-receive.sh` (see above). The pipeline's own gitleaks scan still runs on every push, and a secret stops the deploy.
