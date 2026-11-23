# Migration techniques

There are two kinds of move:
- **New instance:** another organisation adopts the product, starting fresh (docs/install.md).
- **Moving an instance:** ffwf, say, goes to a new forge or cluster and keeps its history.

Each technique below was used, or hit as a problem, in the Johnopia trial (akb #514).

## Repos

| Repo kind | Technique | Notes |
|---|---|---|
| **Platform repo, new instance** | `install/new-instance.sh`: this product plus the new instance's own files | No other instance's tenants, environments, promotions or stacks come along. Upgrades are the same drop (docs/install.md). |
| **Platform repo, same instance moving** | Full mirror (`git push --mirror`), then one commit that changes `instance.yaml` (`forge_ssh`, `compliance_url`, `platform_repo` if renamed) | History is the deployment record: approvals, promotions and environment changes are commits. Keep it. |
| **Compliance repo** | New instance: `catalogs/` and `profiles/` only. Moving: a mirror plus **releases** | Evidence and released packages are forge releases with assets, not files. Plain git doesn't carry them. Use Forgejo's migration (`POST /repos/migrate` with `releases: true`) or copy each release's assets. |
| **App repos, and CI/CD's own app repos (dashboard, factory)** | `git push` of their branches. Use Forgejo's migration if their issues and PRs matter | **An instance's fork of an app may carry one instance commit.** The dashboard's `cicd.yaml` egress names the forge's address, which differs per instance (ffwf: a tailnet IP; Johnopia: the cluster's own gateway). Rebase that commit onto upstream. |
| **IaC wrapper repos** (`<iac_org>/<app>`) | Moving: mirror. New instance: let `tools/wrap.py` make them again when the apps are enrolled | They hold generated files and follow their source. Wrapping again is cheaper than carrying them over. |

## Names to change when moving

- **`instance.yaml`** in the platform repo.
- **The platform repo's Actions settings:**
  - secrets `CICD_BOT_TOKEN`, `CICD_HOOK_SECRET`, `CICD_RUNTIME_KUBECONFIG`;
  - variables `CICD_BOT_USER`, `CICD_CLUSTER`.
  Secrets are never exported. Make them again.
- **Webhooks on every enrolled repo:** run `tools/enroll.py` (or `wrap.py`) again with the new
  `--hook-url`.
- **Flux:** the GitRepository URL and its deploy key (`clusters/<cluster>/flux-entry.yaml`).
- **Dashboard:** the `dashboard-instance` ConfigMap, a new OAuth app on the new forge, and
  `dashboard-platform`.
- **Factory:** `FORGE_URL` and `FACTORY_REPO` on the controller, `factory-bot`'s password, and
  grants. Grants are collaborator entries on each repo, so they move with the repo only through
  Forgejo's migration. Otherwise users grant again.
- **Runners:** register them with the new forge. The workflows use the `cicd` label on every
  instance.

## Problems the trial found, and what changed

| Problem | Fix |
|---|---|
| Code defaults named ffwf: the IaC org, the tenant, the forge SSH URL, the compliance link | `instance.yaml`, read by `tools/` and by the dashboard |
| Workflows ran on `ffwf-k8s` | `runs-on: cicd`. c-local's runners take both labels. |
| The product's tests read the instance's `clusters/c-local` | `tests/fixtures/clusters` |
| The dashboard's tests assumed the state repo was named `ffwf/cicd-ref-arch`; the pipeline sets `STATE_REPO` to its own repo | Tests use `platform.STATE_REPO` |
| The dashboard's deployment hard-coded ffwf's forge, state repo and cluster | ConfigMap `dashboard-instance` (optional; the code defaults are ffwf's) and ConfigMap `dashboard-theme` |
| A forge behind a private CA | Runner: an init container appends the CA to the system bundle, plus `NODE_EXTRA_CA_CERTS`. Dashboard: ConfigMap `ca-bundle` and `SSL_CERT_FILE`. Factory: `CA_BUNDLE_CONFIGMAP` mounts it into sessions for git, curl, Python and Node. Flux: SSH to the forge's in-cluster service. |
| In-cluster DNS for the instance's public names | Lab: CoreDNS `rewrite` of `*.<zone>` to `traefik.gateway-system`. k0s's own CoreDNS is left out, because it reverts edits. |
| One bot for CI/CD and the factory (ffwf) | Johnopia: `delivery-bot` and `factory-bot`, no org ownership, team write only where each needs it. It works without code changes: the code never assumed one account. |
| Approval needed write on the platform repo | `spec.approvers` and the dashboard's Sign off (docs/promotion.md) |
| An upgrade recorded a product commit that a later rebase replaced | Run `new-instance.sh` from a commit that is already pushed upstream |
| The lab bootstrap's generated admin password ended with a newline | Fixed in `bootstrap.sh` |

## Still open

- **Product and instance state share one repo.** The drop model (`product-paths`) works.
  Splitting them, with the instance repo pinning a product version, would make upgrades a version
  bump.
- **Egress rules name addresses.** A symbolic target (`forge`, `gateway`), resolved per cluster,
  would remove the per-instance commit in app repos.
- **Images are built per instance**, from each instance's own forge. Signing keys and the
  registry are per instance too. Sharing signed images between instances isn't designed yet.
