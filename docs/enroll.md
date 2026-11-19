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
  python3 tools/enroll.py --repo ffwf/cicd-demo-app --app demo --cluster c-local --owner alice
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

## Secrets at push

The forge-side hook `forge/pre-receive-gitleaks` refuses pushes that add a secret. It is an instance change, made by the forge admin:
1. put `gitleaks` (the version in `actions/setup/tools.txt`) on the forge's PATH;
2. install the script as a `pre-receive` hook for the enrolled repos, in each repo's `hooks/pre-receive.d/` on the forge host.

Don't use Forgejo's per-repo git-hook editor (`DISABLE_GIT_HOOKS = false`) for this: it lets every repo admin run code on the forge.

## Limits (for a demo)

- **The app repo holds the bot token.** The bot can push to this repo, so anyone who can change the app repo's workflow can deploy anything. In a real setup:
  - the developers can't edit `.forgejo/` (protected file patterns, or a separate CI owner);
  - or the app's pipeline only asks the platform to build, through a workflow dispatch.
- **Enrollment names a repo, not people.** Who may push code is the app repo's own access control.
