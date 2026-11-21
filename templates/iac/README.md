# {app}: infrastructure

This repo is how **{app}** is built and deployed on the platform (cicd-ref-arch, docs/enrollment.md,
mode `wrapped`). The code is the submodule `src/` → `{source}`; its own deploy files, if any, are ignored.

| file | what |
|---|---|
| `Dockerfile` | how the image is built from `src/` |
| `cicd.yaml` | name, hosts, scaling, test command |
| `deploy/` | the Kubernetes base: resources, probes, the Service |

A push to `{source}` moves `src/` here (`{update}`: {update_how}), and that commit builds and deploys.
Change how the app runs by changing this repo.
