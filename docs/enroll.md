# Enrolling an app

The platform is the product; an app's developers use it without access to it. An admin enrolls each app once. After that, the developers push code and nothing else: the pipeline, its token and the policy belong to the platform.

| The app's developers | The platform admin |
|---|---|
| Code, tests, `Dockerfile`, `deploy/` | Enrolls the app: `tenants/<app>.yaml` |
| `cicd.yaml`: test command, URL patterns, idle time | The app repo's Actions secret and variables |
| `security/`: suppressions, stricter settings | The pipeline workflow in the app repo |
| Requests a promotion | Approves promotions (someone other than the requester) |

Example: [ffwf/cicd-demo-app](https://forge.goblincorps.com/ffwf/cicd-demo-app).

## 1. The app meets the contract

See `templates/app/` and [contract.md](contract.md):
- `cicd.yaml` at the path you enroll;
- a kustomize base in `deploy/` whose image is the literal name `app-image`;
- a Dockerfile with its base pinned by digest;
- a `/healthz` readiness probe;
- `security/policy.yaml` and `security/vex.openvex.json`, which can start empty.

## 2. Enroll

From a checkout of this repo, with a token that is an admin of the app repo:

```sh
FORGEJO_TOKEN=<admin token> CICD_BOT_USER=ffwfbot CICD_BOT_TOKEN=<bot token> \
  python3 tools/enroll.py --tenant ffwf --repo ffwf/cicd-demo-app --app demo --cluster c-local --owner alice
git add tenants/demo.yaml && git commit -m "enroll demo" && git push
```

It:
1. writes `tenants/<app>.yaml`. Deploys of the app are refused until it is pushed, and only ever accepted from the enrolled repo, on the enrolled clusters;
2. sets the app repo's secret `CICD_BOT_TOKEN` and its variables `CICD_BOT_USER` and `CICD_CLUSTER`;
3. commits `templates/ci/app.yaml` to the app repo as `.forgejo/workflows/cicd.yaml`. That commit starts the first run.

Run it again to update the workflow or rotate the token.

## 3. What the developers then get

- **Push to the dev branch** (`environments.dev.branch` in `cicd.yaml`): live at `<app>-dev.<cluster>.<zone>`.
- **Any other branch:** live at `<app>-<branch>.<cluster>.<zone>`. Deleting the branch removes it within a minute: the app's pipeline asks the `environments` workflow here to clean up.
- **Every run:** a test record and a security record, shown in the run's summary. Dev and branch deploys go ahead on findings; a secret stops them.
- **Prod:** `request-promotion` in this repo, approved by someone else. See [promotion.md](promotion.md) and [security.md](security.md).

## Self-service

After enrollment, anyone with **write on the app repo** helps themselves. There are two ways:
- **Dashboard:** `cicd-dashboard`, signed in through the forge.
- **Forge:** Actions → `cicd` → Run workflow.

Either way the request is dispatched to the app's own pipeline, which carries it out and records who asked:

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
2. run `forge/install-pre-receive.sh <repositories root> <gitleaks path>`. The repositories root is `[repository] ROOT` in `app.ini`. The script installs the hook into `hooks/pre-receive.d/` of this repo and of every repo in `tenants/`. Run it again after enrolling an app.

Don't use Forgejo's per-repo git-hook editor (`DISABLE_GIT_HOOKS = false`) for this: it lets every repo admin run code on the forge.

## Limits (for a demo)

- **The app repo holds the bot token.** The bot can push to this repo, so anyone who can change the app repo's workflow can deploy anything. In a real setup:
  - the developers can't edit `.forgejo/` (protected file patterns, or a separate CI owner);
  - or the app's pipeline only asks the platform to build, through a workflow dispatch.
- **Enrollment names a repo, not people.** Who may push code is the app repo's own access control.
