# Evidence: scans kept as releases on CI/CD's evidence repo

The pipeline owns the scans it produces, so it keeps them on CI/CD's own repos. It never writes them to an app's repo: developers give the pipeline read access to their code, and the pipeline gives them read access to its records.

| What | Where | How long |
|---|---|---|
| A job's output (`deliver`, `runtime`, `ci-result-test`, `stack`) | **artifacts** of the platform's pipeline run | the forge's artifact retention |
| An environment's scans: SBOMs, each scanner's output, `security.json`, the OSCAL assessment and SSP | **assets of one release** on the evidence repo, tag `<cluster>/<app>/<env>/<digest>` | retention below |
| Which release, with each file's sha256 and size | `envs/<cluster>/<app>/<env>/evidence/evidence.json` in this repo | with the environment |
| The verdicts that pages and promotion requests read | this repo, as before: `security-record.json`, `findings-source.json`, `evidence/assessment-summary.json`, `evidence/approval.json` | with the environment |

The tag ends in a digest of the files' names and sha256s. A retried job, or a re-assessment that changes nothing, reuses the release it already made. A new version is always complete on its own: files the previous version had and this run didn't produce are carried over.

## Who writes and reads it

| Writes | When |
|---|---|
| `cicd.py render` (the deploy) | dev and branch environments, with all of the build's scan output |
| `cicd.py apply-due` | prod: the promotion's re-scan plus the build's evidence. The applied promotion records the same `evidence.json` |
| `cicd.py reassess` | fetches the kept SBOM, re-gates, and publishes the new version |
| `evidence.py prune` (environments workflow) | applies retention |

The dashboard reads the SBOM for its packages and advisories (once per sha256), serves `/api/apps/<app>/envs/<env>/<doc>` from the release, and copies the files into a compliance release package. Each file is checked against its sha256 in `evidence.json`. A file that differs shows **evidence altered**, and a file that's gone shows **evidence missing**. Neither is used.

Who can read the scans is decided by who can read the evidence repo. Where per-app restriction matters, a tenant can name a repo of its own, with its own readers.

Here the evidence repo is the compliance repo (`ffwf/cicd-compliance`), so scans and IT Security's records share one set of readers. Its releases are the scans; its git tree is still the OSCAL content, the ledger, the advisories and the release packages. Release tags don't start its `assess` workflow, which runs only on pushes to `main`.

## Configuration

```yaml
# clusters/<cluster>/cicd-cluster.yaml: the default for every app on the cluster
evidence: {repo: ffwf/cicd-compliance, keep: 1}           # keep: versions per environment ("latest only")

# tenants/<app>.yaml: overrides any key; on its own it turns evidence releases on for that app alone
spec:
  evidence: {keep: 3, days: 90}                           # the last 3, and anything younger than 90 days
```

Retention per environment:
- the newest `keep` versions stay;
- versions younger than `days` stay;
- any version still named by an environment or a pending promotion stays.

When an environment is removed, its versions go once they are older than `days` (immediately if `days` isn't set). Without an `evidence` setting, evidence stays inline in this repo, as it did before.

## Moving existing evidence

`tools/evidence.py backfill --cluster <c> --git-commit <sha>` publishes each environment's and each pending promotion's inline evidence, and replaces those files with `evidence.json`. Applied promotions keep checksums only; their files remain in this repo's history at `<sha>`.
