# Demo runbook (c-local)

Run each step from a machine on the tailnet. The browser must trust the cluster CA (k-ca) for https; plain http works without it.

| # | Do | See |
|---|---|---|
| 1 | Change `VERSION` in `examples/hello/app.py` and push to `master`. | Actions: `hello` runs `test`, then `deliver`. The test job's artifact `ci-result-test` holds the result record. |
| 2 | Wait for `deliver` (about 1–2 min warm). | A bot commit `deploy dev: hello ...` lands in `envs/c-local/hello/dev/`. Within a minute, `https://hello-dev.c-local.k.ffwf.net/` shows the new version and commit. |
| 3 | Push a branch: `git switch -c feat/demo && git commit --allow-empty -m demo && git push -u origin feat/demo`. | `https://hello-feat-demo.c-local.k.ffwf.net/`, in namespace `hello-feat-demo`. |
| 4 | Delete the branch: `git push origin :feat/demo`. | The `environments` workflow removes `envs/c-local/hello/branch-feat-demo/`, and Flux deletes the namespace. |
| 5 | Leave dev idle for 15 minutes (or set `idleSeconds: 60` for the demo), then run `curl -sw '%{http_code} %{time_total}s\n' -D- https://hello-dev.c-local.k.ffwf.net/api/info`. | `kubectl -n hello-dev get deploy` shows `0/0` before the request. The request waits, then returns `200` with `X-KEDA-HTTP-Cold-Start: true`. There is no error and no reload. |
| 6 | Actions → `request-promotion` → app `hello`, from `dev`, `not_before` a few minutes ahead. | A PR whose files are exactly the dev manifests and digest. |
| 7 | A second person approves and merges it. | At or after `not_before`, the `environments` workflow commits `envs/c-local/hello/prod/`, and `https://hello.c-local.k.ffwf.net/` serves that build. `promotions/done/<id>/promotion.yaml` records who approved it. |
| 8 | Open the `deliver` artifact. | `security/summary.json`, `sbom.spdx.json` and `signature.json` (`signed: false`): the report-only security slots. |

Checks for the operator:

```sh
export KUBECONFIG=kubeconfig.c-local
flux get kustomizations | grep -E 'cicd|gateway|keda|traefik|buildkit'
kubectl get interceptorroutes,scaledobjects -A
kubectl -n keda logs deploy/keda-add-ons-http-interceptor --tail=20
```
