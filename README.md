# cicd-ref-arch

A reference architecture for CI/CD onto Kubernetes. Forgejo Actions run the CI, and Flux does the deploys from git.

The demo story, end to end:

1. **Push.** CI runs the tests, posts a result, builds an image and pushes it by digest.
2. **Dev and branch environments.**
   - A push to `master` updates `<app>-dev.<cluster>.<zone>`.
   - A push to any other branch updates `<app>-<branch>.<cluster>.<zone>`.
   - Both URL patterns are set per app in `cicd.yaml`.
3. **Scale to zero.**
   - After 15 minutes with no requests, the app's pods scale to zero.
   - The next request is held at the gateway while one pod starts, then answered. The user sees a short delay, not a 502 or "no available server", and doesn't need to reload.
4. **Security.**
   - Every build is scanned: secrets, code, config, an SBOM, and known vulnerabilities in the image.
   - Dev and branch deploys report findings and go ahead. A secret is the exception: it stops any deploy, and a forge hook refuses it at push.
   - A prod promotion is re-scanned and refused if it fails the policy.
   - False positives are records with a reason and an expiry, never code changes, and the promotion PR shows them. See [docs/security.md](docs/security.md).
5. **Approved, scheduled promotion.**
   - A person requests promotion of a dev build to `<app>.<cluster>.<zone>` and/or a custom domain, with a not-before time.
   - A different person approves the pull request.
   - A scheduled job applies the promotion once it is due.

6. **Apps in their own repos.** An admin enrolls an app ([docs/enroll.md](docs/enroll.md)). Its developers then push code and get all of the above, without access to the platform. Example: [ffwf/cicd-demo-app](https://forge.goblincorps.com/ffwf/cicd-demo-app).

Agents that turn CI results into pull requests are out of scope. They come next, in `ffwf/agentic-ref-arch`.

## Layout

| Path | What it holds |
|---|---|
| [`docs/`](docs/) | [architecture](docs/architecture.md), [the app contract](docs/contract.md), [promotion](docs/promotion.md), [security](docs/security.md), [enrolling an app](docs/enroll.md), [demo runbook](docs/demo.md), [decisions and open questions](docs/decisions.md) |
| `platform/` | Cluster add-ons the pipeline relies on: Gateway API with Traefik, KEDA with the HTTP add-on, BuildKit. Applied by Flux. |
| `clusters/<name>/` | Flux entry points for one cluster: the platform, plus the environments CI writes. |
| `envs/<cluster>/<app>/<env>/` | **Written by CI, never by hand.** One directory per running environment. Deleting one removes the environment (Flux prune). |
| `promotions/` | Promotion requests. Each arrives through an approved pull request and is applied by the `environments` workflow once due, approved and through the security gate. |
| `templates/` | What an app repo starts from: `cicd.yaml`, a `deploy/` base, `security/` records, a pre-commit hook; and the CI workflow enrollment installs. |
| `tenants/` | One file per enrolled app: its repo and clusters. Written by an admin with `tools/enroll.py`. |
| `security/` | The platform's security policy floor and its opengrep rules. |
| `forge/` | The forge-side pre-receive hook that refuses secrets at push. |
| `actions/` | Composite actions the workflows use: setup, test, build, security, sign, deploy-env. |
| `tools/cicd.py` | Renders environments, sanitises branch names, queues and applies promotions. Python with PyYAML. |
| `tools/security.py` | Runs the scanners, normalises findings, gates them by policy. |
| `examples/hello/` | The demo app. Its pipeline is `.forgejo/workflows/hello.yaml`. |

## Quick reference

```sh
# what URLs would this app get?
tools/cicd.py hosts examples/hello/cicd.yaml --cluster local --zone k.ffwf.net --branch feat/Login-Page

# render an environment locally (the same thing CI does)
tools/cicd.py render examples/hello/cicd.yaml --env branch --branch feat/x \
  --cluster local --zone k.ffwf.net --image localhost:5000/hello@sha256:... --out /tmp/envs

# request a promotion (then open a PR with the file it writes)
tools/cicd.py request-promotion --app hello --cluster local --from dev --not-before 2026-11-20T15:00:00Z
```
