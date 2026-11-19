# Architecture

CI builds images and writes the desired state into git; Flux applies it; the KEDA HTTP add-on handles scale-to-zero. Nothing in CI holds cluster credentials.

```
 developer ── git push ──▶ Forgejo ──▶ runner (ffwf-k8s label, ns ci)
                                         │ 1 test          → ci-result/v1 record, job status
                                         │ 2 build         → buildctl ──▶ BuildKit (ns buildkit) ──▶ registry
                                         │ 3 sbom/scan/sign → report-only security records
                                         │ 4 deploy-env    → commit envs/<cluster>/<app>/<env>/ to the state repo
                                         ▼
                              state repo (this repo) ◀── Flux GitRepository (1 m poll)
                                         │
                                         ▼  Kustomization cicd-envs (prune)
                  namespace <app>-dev / <app>-<branch> / <app>:
                    Deployment (no replicas), Service, NetworkPolicy, InterceptorRoute, ScaledObject

 browser ─▶ *.<cluster>.<zone> (DNS: tailnet proxy address)
         ─▶ Traefik (Gateway "edge", ns gateway-system)
         ─▶ HTTPRoute apps-wildcard ─▶ KEDA interceptor (ns keda)
                                        │ picks the InterceptorRoute by Host
                                        │ app at 0 replicas: holds the request, signals the scaler
                                        ▼ forwards once a pod is Ready
                                      app Service ─▶ pod
```

## The pieces

| Piece | Where | Job |
|---|---|---|
| Forgejo Actions runner | ns `ci`, label `ffwf-k8s` | Runs the pipeline. Unprivileged, no docker, no Kubernetes API access. |
| BuildKit (rootless) | ns `buildkit` | Builds images for the runners and pushes them by digest. It runs in its own namespace so the runners' namespace keeps its restricted settings. |
| Registry | the cluster's own (`localhost:5000` mirror on c-local) | Image storage. The push and pull names come from `clusters/<c>/cicd-cluster.yaml`. |
| State repo | `envs/`, `promotions/` in this repo | The desired state of every environment, written by CI and reviewed for prod. |
| Flux | ns `flux-system` | Applies `platform/` and `envs/<cluster>/`. Prune removes environments whose directory was deleted. |
| Traefik | ns `gateway-system` | The Gateway API controller: one Gateway `edge` covering `*.<cluster>.<zone>` on 80 and 443. |
| KEDA + HTTP add-on | ns `keda` | The interceptor counts requests, holds them during a cold start, and drives a `ScaledObject` (min 0, `cooldownPeriod` = idle time). |
| cert-manager | existing | A wildcard certificate for `*.<cluster>.<zone>` from the cluster's issuer. |
| Exposure | `clusters/<c>/exposure/` | How people reach the Gateway. On c-local, a tailnet proxy whose address ExternalDNS publishes as `*.c-local.k.ffwf.net`. |

## Environments

| Environment | Trigger | Namespace | Default URL | Directory |
|---|---|---|---|---|
| dev | push to `master` (`environments.dev.branch`) | `<app>-dev` | `<app>-dev.<cluster>.<zone>` | `envs/<c>/<app>/dev/` |
| branch | push to any other branch, except `exclude` patterns | `<app>-<slug>` | `<app>-<slug>.<cluster>.<zone>` | `envs/<c>/<app>/branch-<slug>/` |
| prod | an approved promotion that is due | `<app>` | `<app>.<cluster>.<zone>` plus `extraHosts` | `envs/<c>/<app>/prod/` |

- **URL patterns** are set per app in `cicd.yaml`. The placeholders are `{app}`, `{cluster}`, `{zone}` and `{branch}`.
- **`{branch}`** is the branch name lowercased, with every run of other characters replaced by `-`. It is cut to fit one DNS label, with a hash suffix when it is cut. A branch named `dev` or `prod` becomes `dev-br` or `prod-br`.
- **Each environment directory** holds:
  - `app.yaml`: the app's `deploy/` base, built at that commit;
  - `platform.yaml`: the NetworkPolicy, InterceptorRoute and ScaledObject;
  - `namespace.yaml`;
  - a kustomization that sets the namespace and the image digest;
  - `cicd.yaml` and `cicd-env.yaml`: data recording what was built and from where.
- **Branch environments are removed** when their branch is deleted, by the `environments` workflow (on delete, and every 5 minutes).

## Scale to zero without errors

The requirement is that a user never sees `502`, `503 no available server`, or a page that needs reloading.

1. **Every request goes to the interceptor.** Traefik sends all `*.<cluster>.<zone>` traffic to the KEDA interceptor, through one platform HTTPRoute. Traefik therefore never routes to a Service with no endpoints, which is where "no available server" comes from.
2. **The interceptor holds requests during a cold start.** At zero replicas, it holds the request and signals the external scaler. KEDA scales the Deployment to 1, and the interceptor forwards the request once an endpoint is ready. The wait is bounded by `timeouts.readiness` (`coldStartTimeout`, default 60 s).
3. **Readiness is polled every second** (the app template's probe). The cold start is image pull (cached after the first time) plus process start plus the first passing probe.
4. **Idle scale-down.** After `idleSeconds` (900) with no requests, KEDA's `cooldownPeriod` scales the Deployment back to 0.
5. **Nothing in the path times out first.** The wildcard route sets no request timeout, and Traefik's defaults set no response timeout.

**Measure it:** `docs/demo.md` step 5 times a cold request. The response carries `X-KEDA-HTTP-Cold-Start: true` when it woke the app.

**Measured on c-local, 2026-11-19 (hello, image cached on the node):**
- One cold request from 0 replicas: `200` in 1.97 s.
- 20 concurrent cold requests: all `200`, in 0.75–1.3 s.
- Warm: about 6 ms.
- An unknown host gets `404` from the interceptor.

**Caveats:**
- Long-lived connections (WebSockets, SSE) keep the app awake, which is the right behaviour, but they count as one request each.
- The interceptor is on the request path for every app. Give it more than one replica on a real cluster.

## Results for people and agents

- **Every job writes a `ci-result/v1` record** (`tools/ci_result.py`), uploaded as an artifact. It holds pass/fail, counts, failures and the log tail.
- **Forgejo's job status** on the commit is the signal.
- **The record** is what an agent reads instead of a log.

`ffwf/agentic-ref-arch` builds on this.
