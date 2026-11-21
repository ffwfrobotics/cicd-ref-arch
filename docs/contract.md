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
| `overlays` | 2 | each deploy-<env>/ overlay builds, passes the same checks as the base, and changes only what spec.overlays.allow lists | warn. Fix the overlay named: it is what that environment would run (an overlay that doesn't build stops the run) |
| `app-image` | 3 | a container's image is `app-image` | warn. Set the app container's image to app-image: the pipeline swaps in what it built |
| `no-replicas` | 4 | the workload sets no spec.replicas | warn. Remove spec.replicas: KEDA sets the count |
| `restricted` | 5 | runAsNonRoot, seccompProfile RuntimeDefault, allowPrivilegeEscalation false, capabilities drop ALL | warn. The pod will be refused: add the securityContext fields named (see templates/app/deploy/deployment.yaml) |
| `readiness` | 6 | each container has a readinessProbe | warn. Add a readinessProbe: without one, requests reach the pod before it listens |
| `service` | 7 | a Service named spec.service.name with port spec.service.port | warn. The gateway can't reach the app: add the Service, or fix spec.service in cicd.yaml |
| `requests` | 8 | each container sets resources.requests | warn. Set resources.requests (e.g. cpu 10m, memory 32Mi) |
| `dockerfile` | 9 | the Dockerfile named in spec.build exists | missing: stops the run. Nothing to run: add a Dockerfile (spec.build.dockerfile in cicd.yaml says where) |
| `base-pinned` | 9 | each FROM names its image @sha256:... | warn. Pin the base image by digest: FROM image:tag@sha256:... |

## After the deploy: the runtime check

The `runtime` job (`tools/runtime.py`) waits for the environment to run the new build, sends one request to its host (which also wakes a scaled-to-zero app), and watches the build's pods for about 90 s. It posts one word as the commit status `cicd/runtime`, and keeps the pod states, events and last log lines it decided from with the run (artifact `runtime`).

| Word | Rule | What it saw | What to do |
|---|---|---|---|
| **not applied** |  | the environment didn't run this build within 5 minutes | Flux hasn't applied it yet: the platform's side, not the app's. The next run checks again |
| **rejected** | 5 | the namespace refused to create the pod (Pod Security restricted, or a quota) | Fix the securityContext fields named (see templates/app/deploy/deployment.yaml) |
| **image pull** | 3 | the image couldn't be pulled | Use the image name app-image in deploy/: the pipeline swaps in what it built. Other images must be pullable here |
| **config error** |  | the container couldn't be created (a missing Secret, ConfigMap or key it refers to) | Create what it names, or remove the reference: secrets go in out of band (contract: Secrets) |
| **out of memory** | 8 | killed at its memory limit | Raise resources.limits.memory, or use less |
| **crash** |  | the process exits (CrashLoopBackOff, or it stopped) | It exits on start: see the last log lines in the run. The main process must keep running in the foreground |
| **unschedulable** | 8 | no node can fit the pod | Lower resources.requests |
| **localhost only** | 7 | the probe's connection is refused and the log shows a 127.0.0.1 or localhost address | Listen on 0.0.0.0, not 127.0.0.1: the probe and the gateway connect from outside the container |
| **not ready** | 6 | running, but the readiness probe never passed | Point the readinessProbe at the port the app listens on and a path that answers 200 |
| **not started** | 7 | no pod of this build started (a scaled-to-zero app wasn't woken by a request) | Check spec.service and spec.workload in cicd.yaml name the Service and Deployment in deploy/ |
| **unreachable** | 7 | ready, but its host gave no answer | The Service must select the pod and target the port it listens on (spec.service in cicd.yaml) |
| **5xx** |  | ready, but the host answers / with a server error | The app answers / with an error: see the log |
| **running** |  | a pod of this build is ready and its host answers below 500 | Running |
