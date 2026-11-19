# Promotion: approved and scheduled

A dev build goes to prod only through a pull request that someone other than the requester approves. The change is applied only at or after the requested time.

```
request ──▶ PR "Promote hello to prod (id)" ──▶ approve + merge ──▶ promotions/pending/<id>/
                                                                         │ every 5 min, or on merge
                                                                         ▼
                                             environments workflow: due? approved? ──▶ envs/<c>/hello/prod/
                                                                                          promotions/done/<id>/
```

1. **Request.** There are two ways:
   - Actions, then `request-promotion`, then Run workflow, with the app, the source environment (`dev`), an optional `not_before` (UTC), and a reason.
   - Or locally: `tools/cicd.py request-promotion --app hello --cluster c-local --not-before 2026-11-20T15:00:00Z`, then open the pull request yourself.

   Either way, the request pins what the source environment runs right now:
   - `app.yaml`: the exact manifests;
   - the image digest;
   - the app's `cicd.yaml`.

   A later dev build doesn't change what was approved.
2. **Approve.** A reviewer reads the PR, which shows the manifests and digest that will run in prod, then approves and merges it.
3. **Apply.** The `environments` workflow runs every 5 minutes and on each merge into `promotions/pending/`. It applies a request only if all of these hold:
   - `notBefore` has passed;
   - the request reached `master` through a merged PR (found through the merge commit, or the commit itself for a squash or rebase merge);
   - someone other than the PR's author and the requester authorized it, either with an approving review or by merging it.

   It then renders `envs/<cluster>/<app>/prod/`, moves the request to `promotions/done/<id>/` with `appliedAt` and the authorization it relied on, and commits. Flux applies the change within a minute. A request that is due but fails these checks turns the run red, and stays pending until it is fixed or removed.
4. **Roll back.** Promote an earlier build: request a promotion from a `promotions/done/<id>` entry, or revert the prod commit through a PR.

## Two locks, not one

1. **Branch protection** on `master`. This is what actually stops a direct change:
   - 1 required approval;
   - stale approvals dismissed;
   - merging limited to people allowed to approve.
2. **The workflow's own check.** It is a second check, and it covers the case where protection is misconfigured or an admin bypasses it.

**Set up once, in Forgejo** (not done yet; see decisions D-5):
- Protect `master`:
  - required approvals 1;
  - dismiss stale approvals;
  - a push whitelist with only the `cicd-bot` user, which CI uses to write dev and branch environments.
- Repo variable `CICD_BOT_USER`, secret `CICD_BOT_TOKEN`. The token must be able to:
  - push to this repo;
  - read pull requests and reviews;
  - open pull requests.

## Custom domains

Hosts that aren't under the cluster zone go in `environments.prod.extraHosts`. Their domain needs three things:
- **DNS:** a CNAME, or an A record pointing at the cluster's public entry point. c-local is tailnet-only today, so this needs a public path, e.g. goblincorps' nginx passing the domain through to the cluster over the tailnet.
- **A certificate:** a Gateway listener per domain (`custom-https`) with its own certificate, from ACME once there is a public path.
- **A route:** a route to the interceptor, which the renderer already writes as `prod/edge/`.

Only the route exists so far. The listener and the public path are open (decisions D-6).
