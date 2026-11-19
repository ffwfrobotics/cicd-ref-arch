# The app contract

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
