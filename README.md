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
4. **Security slots.** The pipeline has steps for an SBOM, a Dockerfile lint, an image scan and a signature. Today they only report and never block. Each is a stub to be replaced once the tooling is chosen (see [docs/security.md](docs/security.md)).
5. **Approved, scheduled promotion.**
   - A person requests promotion of a dev build to `<app>.<cluster>.<zone>` and/or a custom domain, with a not-before time.
   - A different person approves the pull request.
   - A scheduled job applies the promotion once it is due.

Agents that turn CI results into pull requests are out of scope. They come next, in `ffwf/agentic-ref-arch`.

## Layout

| Path | What it holds |
|---|---|
| [`docs/`](docs/) | [architecture](docs/architecture.md), [the app contract](docs/contract.md), [promotion](docs/promotion.md), [security slots](docs/security.md), [demo runbook](docs/demo.md), [decisions and open questions](docs/decisions.md) |
| `platform/` | Cluster add-ons the pipeline relies on: Gateway API with Traefik, KEDA with the HTTP add-on, BuildKit. Applied by Flux. |
| `clusters/<name>/` | Flux entry points for one cluster: the platform, plus the environments CI writes. |
| `envs/<cluster>/<app>/<env>/` | **Written by CI, never by hand.** One directory per running environment. Deleting one removes the environment (Flux prune). |
| `promotions/` | Promotion requests. Each arrives through an approved pull request and is applied by `promote-due`. |
| `templates/` | What an app repo copies: `cicd.yaml`, a `deploy/` base, a Dockerfile, a CI workflow. |
| `actions/` | Composite actions the workflows use: setup, test, build, sbom, scan, sign, deploy-env. |
| `tools/cicd.py` | Renders environments, sanitises branch names, queues and applies promotions. Python with PyYAML. |
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
