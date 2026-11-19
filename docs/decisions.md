# Decisions and open questions

## Decided

| ID | Decision | Why |
|---|---|---|
| D-1 | **CI never touches the cluster API.** It writes desired state to git, and Flux applies it. | Runners run anyone's workflow code. With no kubeconfig to steal, every deploy is a reviewable commit, and prune makes cleanup a directory delete. |
| D-2 | **State lives in this repo** (`envs/`, `promotions/`) for the demo. `deploy-env` takes a `state-repo` input, so moving the state to its own repo later is a variable change. | One repo is simpler to demo. A separate state repo keeps bot commits out of the platform's history. |
| D-3 | **Scale to zero uses the KEDA HTTP add-on** (InterceptorRoute API, v0.16), behind one wildcard HTTPRoute. | It holds requests during a cold start (the "no reload, no 502" requirement), works behind any Gateway API controller, and needs no change to the app's Deployment. Knative Serving does the same with a heavier footprint and its own workload API. Sablier is tied to proxy plugins. |
| D-4 | **Images are built by rootless BuildKit** in its own namespace (PSA privileged), driven by `buildctl` from unprivileged runners. | Runners have no docker daemon and stay at PSA baseline. One builder also shares its layer cache. |
| D-7 | **Traefik v3.7 is the Gateway API controller** (Gateway API v1.6.3 CRDs, standard channel). | Chosen in the base-stack doc: "traefik, modern gateway protocol". |
| D-8 | **Security steps report only** until docs/security.md is decided. | The user asked that security not block or dominate the CI/CD work, but have slots from day one. |
| D-9 | **c-local is the demo cluster.** The runner, k-ca, ExternalDNS and the tailnet are already there. Everything new is in its own namespaces. | Faster than a new cluster. A fresh k0s remains the portability test before anything is published. |

## Open: need John

| ID | Question | Default until answered |
|---|---|---|
| D-5 | **Bot identity and branch protection.** A `cicd-bot` Forgejo user with write on this repo, token as secret `CICD_BOT_TOKEN`, variable `CICD_BOT_USER`; `master` protected with 1 required approval and a push whitelist of `cicd-bot`. | Nothing deploys until the bot token exists. Promotions are still checked by the workflow, but master is unprotected. |
| D-6 | **A public path for custom domains.** c-local is tailnet-only. Options: goblincorps nginx passes chosen domains through the tailnet to the Gateway; or a cluster with a public LoadBalancer. | Custom-domain routes are rendered but unreachable. |
| D-10 | **Who may approve promotions.** Any repo collaborator with approve rights except the requester, or a named team. | Any approver except the requester. |
| D-11 | **Retention.** How long branch environments live after the last push, apart from branch deletion. | Until the branch is deleted. |
| D-12 | **Where this repo goes public, and when.** The base-stack doc proposed a scrubbed export later. This repo still has `ffwf.net` names in `clusters/c-local/`. | Private. |
