# Enrollment modes: who owns how an app is built and deployed

An enrolled app is built and deployed from its **IaC root**: the repo and path named in `tenants/<app>.yaml` (`spec.repo`, `spec.path`). The IaC root holds `cicd.yaml`, the deploy base (`deploy/`, and `deploy-<env>/` overlays if any), the Dockerfile and the test command. The code it builds is either in the same place, or in **sources**: git submodules of the IaC root.

Where the IaC root sits is the only difference between the modes. The pipeline does the same thing in all of them: it checks out the IaC root with its submodules, then reads `cicd.yaml` there.

| Mode | IaC root (`spec.repo`, `spec.path`) | Code | Who controls build, deploy and resources |
|---|---|---|---|
| **direct** | the app repo, `.` | the same repo | the app's developers |
| **wrapped** | `ffwf-iac/<app>`, `.`: a repo the platform bot creates and owns | submodule `src/` → the app repo (imported into this forge) | the platform's owners. Developers get read access, or PRs if allowed |
| **monorepo** | the monorepo, `apps/<project>` | submodules of the monorepo, or code inline | the monorepo's owners |
| **monorepo with a config repo** | the monorepo, `<config>/apps/<project>` | sibling submodules of the monorepo | the config repo's owners |

`cicd.yaml` says where the code is: `spec.build.context` is relative to the IaC root, for example `src` or `../../services/api`. `spec.build.dockerfile` names the IaC root's Dockerfile. The test command runs in the IaC root, so it can test the code in `src/` with tests the owners wrote.

## The tenant record

```yaml
apiVersion: cicd.ffwf.net/v1alpha1
kind: Tenant
metadata: {name: mabel}
spec:
  kind: App                         # App (default) | Stack (docs/stacks.md)
  mode: wrapped                     # direct (default) | wrapped | monorepo
  tenant: ffwf
  repo: ffwf-iac/mabel              # the IaC root's repo
  path: .                           # the IaC root inside it
  sources:                          # submodules of the IaC root that hold code (none in direct mode)
  - path: src
    repo: ffwf/mabel-deploy         # the submodule's repo on this forge
    branch: main                    # the source branch that maps to the IaC root's dev branch
    update: follow                  # follow | pin
  clusters: [c-local]
```

A record without `mode` or `sources` is direct, which is every record written before this change.

## Following and pinning sources

A push to a source repo reaches the dashboard by its webhook. The dashboard dispatches the pipeline with `action: bump`. The bump moves the submodule in the IaC root:

| `update` | A push to the source's `branch` | A push to another source branch `feat/x` |
|---|---|---|
| `follow` | a commit on the IaC root's dev branch: `bump src to <sha7>` | a commit on the IaC branch `src/feat-x`, created from the dev branch if it doesn't exist |
| `pin` | a PR from `bump/src-<sha7>` to the dev branch; nothing deploys until it is merged | the same, on `src/feat-x` |

Each bump commit carries trailers: `Source-Repo:`, `Source-Commit:` and `Requested-by:` (the pusher). That commit is an ordinary push to the IaC root, so it builds, deploys and is checked like any other. The environment records which source commit it runs (`cicd-env.yaml`, `sources:`). A deleted source branch removes its `src/<slug>` IaC branch, which removes the branch environment.

The IaC root's own branches build as usual. A change to `deploy/` alone is a deploy of the same source commit with new settings.

## What intake does with the source's own files

A source may carry its own `deploy/`, `cicd.yaml` or Dockerfile: it might have been a direct app once, or a developer added them. In wrapped and monorepo modes they are **ignored**. Intake reports them as `ignored`, saying the IaC root owns them. They can be wrong without breaking anything.

## Enrolling from the dashboard

**Add app** asks for a URL and a mode:
- **direct:** the repo is imported (or used, if it's already on this forge) and enrolled as it is (docs/enroll.md).
- **wrapped:** the bot imports the repo and creates `ffwf-iac/<app>` from `templates/iac/`. It adds the import as `src/`, then runs intake in generate mode: the Dockerfile (picked from what the source contains, for example nginx for a static site), the deploy base and `cicd.yaml` are **committed to the IaC repo** by the bot. Nothing is pushed to the source repo. Webhooks go on both repos.
- **monorepo:** the dashboard lists the monorepo's `apps/*/` folders (or its submodules) and enrolls the ones picked, each with its own tenant record pointing into the shared IaC root.

Each enrollment is `pending` until an admin approves it, as before.
