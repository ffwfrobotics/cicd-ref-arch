# The app contract

<!-- generated from contract.yaml by `tools/intake.py doc`: edit that file, not this one -->

An app that meets these points deploys through this pipeline with no platform changes.

| # | Rule | Why |
|---|---|---|
| 1 | **`cicd.yaml`** at the app's root: name, test command, environments, scale-to-zero settings (see `templates/app/cicd.yaml`). | The pipeline reads everything app-specific from here. |
| 2 | **`deploy/` is a kustomize base** with no namespace, no hostnames, no cluster names. | One base renders into every environment on every cluster. |
| 3 | **The container image is the literal name `app-image`.** | The environment overlay replaces it with `<registry>/<app>@sha256:...`. Deploys are by digest, never by tag. |
| 4 | **No `replicas`** on the scaled workload. | KEDA owns the count (0 when idle); a fixed value would fight it on every Flux apply. |
| 5 | **Pods pass Pod Security `restricted`**: non-root, no privilege escalation, all capabilities dropped, RuntimeDefault seccomp. | Each environment namespace enforces it. |
| 6 | **A readiness probe on a cheap endpoint**, `periodSeconds: 1`. | A cold start lasts until the first passing probe. |
| 7 | **The Service named in `cicd.yaml`** fronts the app on the port named there. | The InterceptorRoute targets it. |
| 8 | **Resource requests set and small.** | Idle apps are at zero anyway; requests are what a running app reserves. |
| 9 | **The Dockerfile pins its base image by digest.** | Builds are reproducible, and the base is the first thing the security slot swaps (docs/security.md). |
| 10 | **Egress is denied unless `cicd.yaml` lists it** (`spec.egress: [{cidr, ports}]`). | Each environment gets a default-deny NetworkPolicy. DNS is always allowed. |

Secrets: not in v1. Apps that need one name it in their base, and the value goes in out of band, the same way the private fleet seeds its Secrets. SOPS with age (decided in the base-stack doc) comes later.

## What the pipeline checks on each push

The `intake` step (`tools/intake.py`) checks each pushed commit before anything is built, and posts the result as commit statuses (`cicd/contract`, and `cicd/contract/<check>` for each one that isn't ok). It never fails the run by itself:
- **assumed**: missing, so a default is used for this run and printed in the log, to commit;
- **warn**: the pipeline goes on, and the hint says what to change;
- **missing**: there is nothing to run, so the run stops after intake.

| Check | Rule | What | When it doesn't hold |
|---|---|---|---|
| `cicd-yaml` | 1 | cicd.yaml exists and names the enrolled app | assumed: default used. No cicd.yaml: defaults used. Commit the generated one (in the run log) and adjust it |
| `tests` | 1 | spec.test.run is set | warn. No test command: set spec.test.run in cicd.yaml |
| `deploy-base` | 2 | the deploy path holds a kustomization.yaml | assumed: default used. No deploy base: one Deployment and Service generated. Commit them (in the run log) to change them |
| `no-namespace` | 2 | no metadata.namespace in the base | warn. Remove metadata.namespace: each environment sets its own |
| `app-image` | 3 | a container's image is `app-image` | warn. Set the app container's image to app-image: the pipeline swaps in what it built |
| `no-replicas` | 4 | the workload sets no spec.replicas | warn. Remove spec.replicas: KEDA sets the count |
| `restricted` | 5 | runAsNonRoot, seccompProfile RuntimeDefault, allowPrivilegeEscalation false, capabilities drop ALL | warn. The pod will be refused: add the securityContext fields named (see templates/app/deploy/deployment.yaml) |
| `readiness` | 6 | each container has a readinessProbe | warn. Add a readinessProbe: without one, requests reach the pod before it listens |
| `service` | 7 | a Service named spec.service.name with port spec.service.port | warn. The gateway can't reach the app: add the Service, or fix spec.service in cicd.yaml |
| `requests` | 8 | each container sets resources.requests | warn. Set resources.requests (e.g. cpu 10m, memory 32Mi) |
| `dockerfile` | 9 | the Dockerfile named in spec.build exists | missing: stops the run. Nothing to run: add a Dockerfile (spec.build.dockerfile in cicd.yaml says where) |
| `base-pinned` | 9 | each FROM names its image @sha256:... | warn. Pin the base image by digest: FROM image:tag@sha256:... |
