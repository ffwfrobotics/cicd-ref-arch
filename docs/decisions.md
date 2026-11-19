# Decisions and open questions

## Decided

| ID | Decision | Why |
|---|---|---|
| D-1 | **CI never touches the cluster API.** It writes desired state to git, and Flux applies it. | Runners run anyone's workflow code. With no kubeconfig to steal, every deploy is a reviewable commit, and prune makes cleanup a directory delete. |
| D-2 | **State lives in this repo** (`envs/`, `promotions/`) for the demo. `deploy-env` takes a `state-repo` input, so moving the state to its own repo later is a variable change. | One repo is simpler to demo. A separate state repo keeps bot commits out of the platform's history. |
| D-3 | **Scale to zero uses the KEDA HTTP add-on** (InterceptorRoute API, v0.16), behind one wildcard HTTPRoute. | It holds requests during a cold start (the "no reload, no 502" requirement), works behind any Gateway API controller, and needs no change to the app's Deployment. Knative Serving does the same with a heavier footprint and its own workload API. Sablier is tied to proxy plugins. |
| D-4 | **Images are built by rootless BuildKit** in its own namespace (PSA privileged), driven by `buildctl` from unprivileged runners. | Runners have no docker daemon and stay at PSA baseline. One builder also shares its layer cache. |
| D-7 | **Traefik v3.7 is the Gateway API controller** (Gateway API v1.6.3 CRDs, standard channel). | Chosen in the base-stack doc: "traefik, modern gateway protocol". |
| D-8 | **Security reports in dev and branch, and gates prod** (superseded the report-only slots, 2026-11-19). See docs/security.md. | Development keeps moving; prod is where findings matter. Secrets block everywhere because the repos are mirrored publicly. |
| D-13 | **Scanning lives in this repo; compliance content in its own.** `actions/security`, `tools/security.py`, `security/` (policy, rules) are here. OSCAL profiles, SSPs, assessment plans and the results generator are a separate repo that reads the records. Not a fork. | The prod gate runs where promotions are applied, so it has to be versioned with them. Compliance content has other reviewers and another pace, and is per system. A fork would be a second copy of the pipeline to keep in step. |
| D-14 | **False positives are records, never code changes.** VEX for vulnerabilities, `ignore` entries with a reason and an expiry for code and config, `.gitleaksignore` fingerprints for secrets. Inline markers are not used. The promotion PR shows the suppressions it carries to prod. | The developer isn't blocked; every exception is reviewed once, by the person who approves prod; an expired ignore gates again. |
| D-15 | **Admins enroll apps** (`tenants/<app>.yaml`, `tools/enroll.py`). Deploys are accepted only for enrolled apps from their enrolled repo. | The platform is the product; app developers push code and need no access to it. The record also stops one repo claiming another app's name. |
| D-16 | **Secrets are refused at push** by a forge pre-receive hook (`forge/pre-receive-gitleaks`), with a reference client hook for fast feedback. | A secret caught after it is in history is already leaked to the mirrors. Installing the hook is an instance change, so it waits for the forge admin. |
| D-9 | **c-local is the demo cluster.** The runner, k-ca, ExternalDNS and the tailnet are already there. Everything new is in its own namespaces. | Faster than a new cluster. A fresh k0s remains the portability test before anything is published. |

## Open: need John

| ID | Question | Default until answered |
|---|---|---|
| D-5 | **Branch protection: required approvals.** Done: bot `ffwfbot`, `CICD_BOT_TOKEN`, `master` protected with a push whitelist (`ffwfbot`, `john`). Open: required approvals are 0, so the workflow's "merger is not the requester" check is the only lock on promotions. | The workflow check. |
| D-6 | **A public path for custom domains.** c-local is tailnet-only. Options: goblincorps nginx passes chosen domains through the tailnet to the Gateway; or a cluster with a public LoadBalancer. | Custom-domain routes are rendered but unreachable. |
| D-10 | **Who may approve promotions.** Any repo collaborator with approve rights except the requester, or a named team. | Any approver except the requester. |
| D-11 | **Retention.** How long branch environments live after the last push, apart from branch deletion. | Until the branch is deleted. |
| D-12 | **Where this repo goes public, and when.** The base-stack doc proposed a scrubbed export later. This repo still has `ffwf.net` names in `clusters/c-local/`. | Private. |
