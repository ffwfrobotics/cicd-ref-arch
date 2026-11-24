# Installing a new instance

An **instance** is one organisation's deployment of this product. It has its own forge, bot
accounts, orgs, platform repo, clusters and brand. ffwf is one instance. The Johnopia trial
(akb #514) is a second one, built from this page on a fresh cluster.

The product and the instance are kept apart:

| | Where | Who changes it |
|---|---|---|
| **Product** | the paths in `install/product-paths`: tools, actions, workflows, platform layer, templates, tests, docs | upstream (cicd-ref-arch) |
| **Instance** | `instance.yaml`, `tenants/`, `envs/`, `promotions/`, `stacks/`, `clusters/<cluster>/` | the instance's admins and its pipeline |

`instance.yaml` holds the names the tools need when a command doesn't give one:
- the platform repo;
- the IaC org;
- the default tenant;
- the forge's SSH URL;
- the compliance link.

Nothing else in the product names an organisation. The `cicd.ffwf.net` API group, its labels and
its rule ids are the product's own names, in the same way as `fluxcd.io`.

## What the cluster needs

- **cert-manager**, with a ClusterIssuer that can issue the apps' wildcard (`CLUSTER_ISSUER`).
- **A CNI that enforces NetworkPolicy.**
- **A default StorageClass.**
- **Flux.**
- **A registry the nodes pull from as `localhost:5000`** (`REGISTRY_PULL`), which BuildKit pushes to.
- **DNS that resolves the instance's names to the gateway, inside the cluster too.** The pipeline,
  the dashboard and the factory reach the forge and the apps by their public names.
- **Exposure for Traefik** (`gateway-system/traefik`, a ClusterIP Service), however the cluster
  exposes things: a LoadBalancer, an ingress proxy or a tunnel.

For a trial, `install/lab-cluster.sh` and `install/bootstrap.sh` provide all of these on one
machine:
- k0s in docker, with its own registry;
- CoreDNS rewriting `*.<zone>` to the gateway;
- local-path storage;
- Flux;
- a private CA, name-constrained to the zone, as ClusterIssuer `lab-ca`;
- cert-manager;
- a Forgejo.

## The instance's own files

Each instance keeps two files with its own state, not with the product:
- **`<name>.env`:** names, zone, forge, repos and bot.
- **`<name>.seed.yaml`:** users, orgs, teams, tokens, the OAuth app and branch protection.

`install/instances/example.env` and `example.seed.yaml` are the template. The Johnopia trial's files
are in `instances/johnopia/` in ffwf's platform repo, which is outside the product paths, so they
never ship.

A product-only copy, for a release or a review, is `install/new-instance.sh --product-only <dir>`.

## Steps (the Johnopia trial, timed on one 12-core host)

| # | Step | Command | Time |
|---|---|---|---|
| 1 | Cluster | `NAME=c-johnopia DIR=/fast/k0s/c-johnopia install/lab-cluster.sh` | ~1 min |
| 2 | Prerequisites and forge | `SECRETS=... install/bootstrap.sh instances/johnopia.env` | ~2 min |
| 3 | Users, orgs, teams, bot token, OAuth app, branch protection | `install/seed.py instances/johnopia.env --api <forge>` | seconds |
| 4 | The platform repo | `install/new-instance.sh instances/johnopia.env <dir>`, then push it to `<platform_repo>` on the new forge | seconds |
| 5 | Flux | a read-only deploy key on the platform repo, Secret `flux-system/platform-deploy-key` (identity, known_hosts), then `kubectl apply -f clusters/<cluster>/flux-entry.yaml` | ~3 min to a ready platform layer |
| 6 | Runner | build `install/runner/Dockerfile` into the registry, register a runner (`forgejo forgejo-cli actions register --secret ... --labels cicd`), Secrets `ci/forgejo-runner` and `ci/actions-cache`, apply `install/lab/runner.yaml` | ~3 min |
| 7 | Platform repo settings | secrets `CICD_BOT_TOKEN`, `CICD_HOOK_SECRET`, `CICD_RUNTIME_KUBECONFIG` (from Secret `cicd-runtime/reader-token`); variables `CICD_BOT_USER`, `CICD_CLUSTER` | seconds |
| 8 | Forge exposure | `install/lab/forge-route.yaml` (the forge's own Gateway and certificate) and, for a lab, `install/lab/exposure.yaml` | seconds |
| 9 | The dashboard, as an app on its own platform | `tools/enroll.py --repo <org>/cicd-dashboard --app dashboard --tenant <org> ...`, push `tenants/dashboard.yaml`, then the out-of-band objects in `dashboard-dev` and `dashboard` (below) | one pipeline run |

### The dashboard's out-of-band objects (per namespace)

- **ConfigMap `dashboard-instance`:**
  - `FORGE_URL`, `STATE_REPO`, `CLUSTER`;
  - `DASHBOARD_BRAND`;
  - `COMPLIANCE_REPO`, `FACTORY_REPO`;
  - `SSL_CERT_FILE=/etc/ca-bundle/bundle.pem` if the forge has a private CA.
- **ConfigMap `dashboard-theme`** (`theme.css`: colours, fonts and the logo as a data: URL). This is
  the white-label step: copy `dashboard/static/theme.css` and change it.
- **ConfigMap `ca-bundle`** (`bundle.pem`: public roots plus the private CA), only for a private CA.
- **Secret `dashboard-oauth`** (`OAUTH_CLIENT_ID`, `OAUTH_CLIENT_SECRET`, `SESSION_KEY`). The forge's
  OAuth app registers both dashboard hosts' `/auth/callback`.
- **Secret `dashboard-platform`** (`token`: the CI/CD bot's token, `hook-secret`: the same value as
  `CICD_HOOK_SECRET`).
- **Secret `dashboard-factory`** (`token`), if the factory runs here.

## Accounts and roles (as seeded for Johnopia)

| Account | Membership | Used for |
|---|---|---|
| `delivery-bot` | write on the platform org and the IaC org (teams), no admin | CI/CD: the pipeline's pushes, statuses, wrapped repos, the dashboard's platform token |
| `factory-bot` | write on `cicd-factory` only; on other repos, only the per-repo grants users make | the software factory: tokens minted per session, none kept |
| developer (`dana`) | write on their team's org (`payments`) | pushes code, requests promotions |
| approver (`avery`) | read on the team's org and the IaC org | signs off promotions in the dashboard (`spec.approvers`, docs/promotion.md) |

The platform repo's `master` lets only `delivery-bot` push and merge. A promotion therefore reaches
master only through the pipeline's PR and a sign-off, either a forge writer's merge or an approver's
rule.

## Upgrading an instance

Run `install/new-instance.sh` again into a checkout of the instance's platform repo, and commit:
- **Product paths** are replaced.
- **`instance.yaml`** records the new product commit. Run it from a commit that is already
  upstream, so the recorded commit exists.
- **The instance's own files** are left alone: tenants, environments, promotions and
  `clusters/<cluster>/`.

When the platform repo's master is protected, the upgrade goes in as a PR that the platform's
account merges.
