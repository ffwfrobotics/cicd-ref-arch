# Demo runbook (c-local)

Run each step from a machine on the tailnet. The browser must trust the cluster CA (k-ca) for https; plain http works without it.

| # | Do | See |
|---|---|---|
| 1 | Change `VERSION` in `examples/hello/app.py` and push to `master`. | Actions: `hello` runs `test`, then `deliver`. The test job's artifact `ci-result-test` holds the result record. |
| 2 | Wait for `deliver` (about 1–2 min warm). | A bot commit `deploy dev: hello ...` lands in `envs/c-local/hello/dev/`. Within a minute, `https://hello-dev.c-local.example.com/` shows the new version and commit. |
| 3 | Push a branch: `git switch -c feat/demo && git commit --allow-empty -m demo && git push -u origin feat/demo`. | `https://hello-feat-demo.c-local.example.com/`, in namespace `hello-feat-demo`. |
| 4 | Delete the branch: `git push origin :feat/demo`. | The `environments` workflow removes `envs/c-local/hello/branch-feat-demo/`, and Flux deletes the namespace. |
| 5 | Leave dev idle for 15 minutes (or set `idleSeconds: 60` for the demo), then run `curl -sw '%{http_code} %{time_total}s\n' -D- https://hello-dev.c-local.example.com/api/info`. | `kubectl -n hello-dev get deploy` shows `0/0` before the request. The request waits, then returns `200` with `X-KEDA-HTTP-Cold-Start: true`. There is no error and no reload. |
| 6 | Actions → `request-promotion` → app `hello`, from `dev`, `not_before` a few minutes ahead. | A PR whose files are exactly the dev manifests and digest. |
| 7 | A second person approves and merges it. | At or after `not_before`, the `environments` workflow commits `envs/c-local/hello/prod/`, and `https://hello.c-local.example.com/` serves that build. `promotions/done/<id>/promotion.yaml` records who approved it. |
| 8 | Open the `deliver` run's summary, or its artifact. | The security gate's table (`warn` in dev), and `build/security/`: SBOMs, each scanner's output, `security.json`, `ci-result-security.json`. |

The same story for an app in its own repo, operated by someone without access to the platform, is in [Demo: an enrolled app](#demo-an-enrolled-app) below.

Checks for the operator:

```sh
export KUBECONFIG=kubeconfig.c-local
flux get kustomizations | grep -E 'cicd|gateway|keda|traefik|buildkit'
kubectl get interceptorroutes,scaledobjects -A
kubectl -n keda logs deploy/keda-add-ons-http-interceptor --tail=20
```

## Demo: an enrolled app

The platform is the product. [ffwf/cicd-demo-app](https://forge.goblincorps.com/ffwf/cicd-demo-app) is a guestbook whose developer only pushes code; an admin enrolled it once ([enroll.md](enroll.md)). Run on c-local on 2026-11-19, with the times seen then.

| # | Who | Do | See |
|---|---|---|---|
| 1 | admin | `tools/enroll.py --repo ffwf/cicd-demo-app --app demo --cluster c-local`, then push `tenants/demo.yaml`. | The app repo gets a push webhook to the dashboard, and no workflow or token. Its next push runs the platform pipeline: tests (5 pass), build, scans, `demo-dev.c-local.example.com` live. The first request wakes it from zero in about 2.4 s. |
| 2 | developer | Push a branch (`feature/dark-mode`). | `demo-feature-dark-mode.c-local.example.com` serves it. The security gate says `warn` (the Werkzeug advisory) and the deploy goes ahead. |
| 3 | developer | On another branch, commit a test fixture that holds a placeholder webhook secret. | The deploy job fails: `fail high secrets generic-api-key tests/fixtures/webhook-example.json:4`. The log prints the line to add if it is a false positive. Nothing is deployed. |
| 4 | developer | Add that line to `.gitleaksignore` with a comment saying why, and push. The code doesn't change. | The branch deploys. With the forge hook installed, the push in step 3 would have been refused, and this same commit would clear it. |
| 5 | developer | Merge both branches to `main` and delete them. | `main` updates dev. The app's pipeline asks the platform to clean up, and both branch environments and their namespaces are gone within a minute. |
| 6 | anyone | `request-promotion` for `demo` from `dev`, while dev still runs Werkzeug 3.0.1. | PR titled `[security: fail]`: one blocking finding, `GHSA-2g68-c3qc-8985`, fixed in 3.0.3. The PR lists all 8 suppressions with their reasons and shows the suppression files it would bring to prod. |
| 7 | developer | Bump Flask and Werkzeug, release 0.2.0. | Dev's gate: `pass`. |
| 8 | anyone, then an approver | Request the promotion again; someone else approves and merges it. | The PR's gate says `pass`. When due, the `environments` workflow re-scans the digest from the registry, applies it, and records the approval and the gate result in `promotions/done/<id>/`. `demo.c-local.example.com` serves 0.2.0. |
