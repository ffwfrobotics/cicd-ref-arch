# App template

Copy this directory into an app repo's root (or a subdirectory), rename `myapp`, and ask an admin
to enroll it (no workflow goes in the app repo: the pipeline runs in the platform). The app then
meets the contract in
[docs/contract.md](../../docs/contract.md):

- `cicd.yaml` names the app, its test command, its environments' URL patterns, and its
  scale-to-zero settings.
- `deploy/` is a kustomize base: no namespace, no hostnames, no `replicas`, the container image
  is the literal name `app-image`, and pods pass the `restricted` Pod Security level.
- A `Dockerfile` at the build context, with its base image pinned by digest.
- A readiness probe on a cheap endpoint (`/healthz`), polled every second: a cold start is as
  fast as the first passing probe.
