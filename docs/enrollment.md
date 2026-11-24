# Enrollment modes: who owns how an app is built and deployed

An enrolled app is built and deployed from its **IaC root**: the repo and path named in `tenants/<app>.yaml` (`spec.repo`, `spec.path`). The IaC root holds `cicd.yaml`, the deploy base (`deploy/`, and `deploy-<env>/` overlays if any), the Dockerfile and the test command. The code it builds is either in the same place, or in **sources**: git submodules of the IaC root.

Where the IaC root sits is the only difference between the modes. The pipeline does the same thing in all of them: it checks out the IaC root with its submodules, then reads `cicd.yaml` there.

| Mode | IaC root (`spec.repo`, `spec.path`) | Code | Who controls build, deploy and resources |
|---|---|---|---|
| **direct** | the app repo, `.`: only one of CI/CD's own repos (the platform's `hello`, `cicd-dashboard`, `ffwfbot/intake-sample`) | the same repo | its owners |
| **wrapped** | `ffwf-iac/<app>`, `.`: a repo the platform bot creates and owns | submodule `src/` → the app repo (imported into this forge) | the platform's owners. Developers get read access, or PRs if allowed |
| **monorepo** | the monorepo, `apps/<project>`: a CI/CD repo holding several apps' IaC roots | submodules of the monorepo | the monorepo's owners |
| **monorepo with a config repo** | the monorepo, `<config>/apps/<project>`: both CI/CD repos | sibling submodules of the monorepo | the config repo's owners |
| **prebuilt** | `ffwf-iac/<app>`, `.`: `cicd.yaml` names an existing image (`spec.image`: repository, tag, digest) and the deploy base | none: nothing is built | the platform's owners. The image comes from elsewhere |
| **build-only** | the repo, `.`: one of CI/CD's own repos | the same repo, one Dockerfile per build | its owners for the images; whoever runs them (another GitOps repo) for everything else. No environment |

`cicd.yaml` says where the code is: `spec.build.context` is relative to the IaC root, for example `src` or `../../services/api`. A source's `path` in the tenant record is its submodule path in the IaC *repo*, so in a monorepo enrolled at `apps/api` the source `services/api` is built with context `../../services/api`. `spec.build.dockerfile` names the IaC root's Dockerfile. The test command runs in the IaC root, so it can test the code in `src/` with tests the owners wrote.

## Who writes where

CI/CD writes only to **its own repos**, listed in `tenants/_writable.yaml`: the IaC org (`ffwf-iac`), the bot's own repos, and the platform, compliance, dashboard and factory repos. That is where bumps, digest updates, commit statuses, webhooks and deploy keys go. A **developer's repo** is read only: CI/CD checks it out to build, test and scan it, and never pushes, comments, posts a status or adds a key there. The developer grants that read access and adds the webhook (the dashboard does both as them when they enroll).

So an IaC root is always one of CI/CD's repos. A developer's repo is enrolled **wrapped**: its code becomes the source `src/` of `ffwf-iac/<app>`. Direct and monorepo enrollment of a developer's repo is refused, and `tools/wrap.py`, `tools/enroll.py` and the dashboard all check the list.

The list is checked where the write happens, not only at enrollment. The bot account may have write on a developer's repo because the developer granted it to the software factory, which shares the account. That grant is not a grant to CI/CD. `tests/test_writes.py` lists every place the platform writes to the forge, and fails when one is added without saying where it writes.

## The tenant record

```yaml
apiVersion: cicd.ffwf.net/v1alpha1
kind: Tenant
metadata: {name: mabel}
spec:
  kind: App                         # App (default) | Stack (docs/stacks.md)
  mode: wrapped                     # direct (default) | wrapped | monorepo | prebuilt | build-only
  tenant: ffwf
  repo: ffwf-iac/mabel              # the IaC root's repo
  path: .                           # the IaC root inside it
  sources:                          # submodules of the IaC repo that hold code (none in direct mode)
  - path: src                       # the submodule's path in the IaC repo (not relative to spec.path)
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

## Prebuilt images

A **prebuilt** app has no code to build: its IaC root's `cicd.yaml` names an image by `spec.image.repository`, `tag` and `digest`. The pipeline copies that digest into the cluster's registry, unchanged, so the digest in the evidence is the one that runs. It pulls the image as an OCI archive, then makes the SBOM and runs the scans exactly as for a build. An image built elsewhere gets the same evidence as one built here.

The tenant record says `mode: prebuilt` and `image: {update: follow | pin}`. Every 5 minutes the environments workflow resolves each prebuilt app's tag (`cicd.py check-images`). When the tag points at a new digest, the digest in `cicd.yaml` is updated:
- **follow:** a commit on the IaC root's dev branch;
- **pin:** a PR from `bump/image`, one per app, updated while it is open.

The commit carries `Image-Repo`, `Image-Tag`, `Image-Digest` and `Previous-Digest` trailers. That push then deploys like any other.

`tools/wrap.py --mode prebuilt --image <repository>:<tag>` creates the IaC repo. The digest, port and user are read from the image's config (`crane`).

## Build-only

A **build-only** app's images are built, scanned and kept as evidence by digest, and nothing else. There is no `cicd.yaml`, no environment, no namespace, no promotion and no bump. It is for software that something else runs: the factory, whose live copy is Flux's (`fleet/apps/factory` in the fleet repo), where a second copy in a dev environment would interfere with the first.

```yaml
spec:
  mode: build-only
  repo: ffwf/cicd-factory
  path: .
  defaultBranch: main               # the dashboard's dev branch (there is no cicd.yaml to say it)
  builds:                           # one image each: <app>-<name> in the cluster registry
  - {name: controller, context: ., dockerfile: Dockerfile}
  - {name: harness, context: harness}          # dockerfile defaults to <context>/Dockerfile
```

Paths are from `spec.path`. Every push runs the pipeline's `image <name>` job once per build: the build, the source and image scans, the gate under the **prod** policy (these images go to production), and the OSCAL self-assessment. A failing gate turns the job red but the result is still recorded, with the gate's verdict next to the digest. For the default branch, each image's scans and `build.json` (the image by digest, the commit, the gate) become one release on the evidence repo, tag `<cluster>/<app>/build-<name>/<digest>`. Retention keeps the newest `keep` per image. Other branches are built and scanned, and their evidence stays in the run's artifacts.

Whoever runs the images takes the digests from there:

```sh
FORGEJO_TOKEN=... FORGEJO_SERVER=https://forge... tools/evidence.py builds --cluster c-local --app factory --branch main
```

prints the newest build of each image (JSON: `image`, `digest`, `commit`, `gate`, `release`). Rendering, promoting, pausing or removing an environment of a build-only app is refused (`cicd.py`, and the pipeline's route). Enroll with `tools/enroll.py ... --build controller:.:Dockerfile --build harness:harness`.

## What intake does with the source's own files

A source may carry its own `deploy/`, `cicd.yaml` or Dockerfile: it might have been a direct app once, or a developer added them. In wrapped and monorepo modes they are **ignored**. Intake reports them as `ignored`, saying the IaC root owns them. They can be wrong without breaking anything.

## Enrolling from the dashboard

**Add app** asks for a URL and a mode:
- **direct:** the repo is imported (or used, if it's already on this forge) and enrolled as it is (docs/enroll.md).
- **wrapped:** the bot imports the repo and creates `ffwf-iac/<app>` from `templates/iac/`. It adds the import as `src/`, then runs intake in generate mode: the Dockerfile (picked from what the source contains, for example nginx for a static site), the deploy base and `cicd.yaml` are **committed to the IaC repo** by the bot. Nothing is pushed to the source repo. Webhooks go on both repos.
- **monorepo:** the dashboard lists the monorepo's `apps/*/` folders (or its submodules) and enrolls the ones picked, each with its own tenant record pointing into the shared IaC root.

Each enrollment is `pending` until an admin approves it, as before.
