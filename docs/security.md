# Security: scans that report in dev and gate prod

Every build is scanned. Development keeps moving: in dev and branch environments, findings are recorded and shown, and the deploy goes ahead. Prod is where findings count: a promotion is re-scanned under the prod policy when it is requested, and the result is a failing check on its PR (`cicd/promotion`) that should stop the merge. What is merged is applied: master is what the cluster runs, so the platform never refuses a merged promotion afterwards. It re-scans again when it applies, and records the result in prod. A secret is the one exception, and blocks every deploy.

Where the merge is the decision, the forge enforces it, if the deployment wants that: on master, require one approval and the `cicd/promotion` check. A deployment whose forge is set up differently still gets the same records: who requested, approved and merged each promotion (`evidence/approval.json` in prod, with `separated: false` when no second person did), and the gate at request and at apply.

```
build ─▶ scan the tree           gitleaks (secrets), opengrep (code), checkov (Dockerfile, manifests)
      ─▶ scan the image          syft SBOM (CycloneDX + SPDX) ─▶ grype, with the app's VEX
      ─▶ gate (tools/security.py) policy for this environment ─▶ pass / warn / fail
      ─▶ deploy dev or branch    the record stays with the environment

request-promotion ─▶ re-scan the pinned digest, gate as prod, show it in the PR
apply-due         ─▶ apply what is merged, when due; re-scan and record the result and the approval in prod
```

## The tools

| Category | Tool | Scans | Notes |
|---|---|---|---|
| `secrets` | gitleaks 8.30.1 (MIT) | the app's files at this commit | History is checked at push by the forge hook (below). |
| `sast` | opengrep 1.33.1 (LGPL-2.1) | the app's code | Rules are the platform's, in `security/rules/`, plus the app's own in `security/rules/` if it has any. Semgrep's registry rules have a proprietary license, so none are used. |
| `config` | checkov 3.4.6 (Apache-2.0) | the Dockerfile and the built deploy base | The open edition has no severities, so every failed check is `high`. Checks the platform satisfies when it renders an environment are ignored in the platform policy. |
| `vuln` | syft 1.57.2, grype 0.122.1 (Apache-2.0) | the built image (OCI tarball in CI; the registry at promotion) | The grype database is cached for a day. |

They are pinned with checksums in `actions/setup/tools.txt`. Each one only reports; `tools/security.py gate` alone decides. Swapping a tool, for Tenable or Trivy for example, means writing a parser to the same finding shape.

## Policy

`security/policy.yaml` in this repo is the platform's floor:

| | dev, branch | prod |
|---|---|---|
| mode | `report`: the job stays green and the record says `warn` | `enforce`: a failing finding fails the promotion PR's `cicd/promotion` check |
| `secrets` | always blocks, at any severity | always blocks |
| `vuln` | high and critical, only when a fixed version exists | same |
| `sast`, `config` | high | high |
| a scanner with no output | counted as a failure | counted as a failure |

An app's own `security/policy.yaml` may make it stricter (`enforce` in dev, a lower `fail_at`, `require_fix: false`). It can never make it looser; anything looser is ignored and noted in the record.

## False positives and accepted risks

Code never changes to satisfy a scanner. Instead, the app records the decision, and the record is reviewed:

| What | Where | Needs |
|---|---|---|
| A vulnerability that doesn't affect the app | `security/vex.openvex.json` (OpenVEX, read by grype) | a status and justification |
| A code or config finding | `ignore:` in `security/policy.yaml`: `rule` (glob), optional `path` (glob over `file:line`) | `reason` and `expires`; an expired ignore gates again |
| A secret that isn't one | `.gitleaksignore`: the `file:rule:line` fingerprint gitleaks prints | a comment saying why |

Inline markers (`# nosemgrep`, `# checkov:skip`, `gitleaks:allow`) are not the way: they hide the decision in code.

**Where the review happens:**
- Every environment keeps copies of these files in `envs/<cluster>/<app>/<env>/suppressions/`.
- A promotion pull request shows the diff between the suppressions running in prod and the ones being promoted, next to the scan result. The person approving the promotion approves the suppressions with it.
- The record lists every suppressed finding with its reason, so nothing disappears.

## Secrets at commit and at push

- **Client:** `templates/app/hooks/pre-commit` runs gitleaks on staged changes. Turn it on with `git config core.hooksPath hooks`. It is fast feedback only: `--no-verify` skips it.
- **Forge:** `forge/pre-receive-gitleaks` scans every pushed commit and refuses the push if any has a secret, so it never enters history or the public mirrors. It honours the pushed tip's `.gitleaksignore`, so clearing a false positive is one commit on top of the refused ones, pushed again as they are. Installing it is an instance change (docs/enroll.md).
- **CI:** the `secrets` category blocks every deploy, even in report mode.

## Records

Everything is in `build/security/` and uploaded as the `deliver` artifact:

| File | What |
|---|---|
| `findings-source.json`, `findings-image.json` | normalised findings (`security-findings/v1`), with tool versions and the sha256 of each native file |
| `gitleaks.json`, `opengrep.sarif`, `checkov.json`, `grype.json` | each scanner's own output: the evidence |
| `sbom.cdx.json`, `sbom.spdx.json` | the image's SBOM |
| `security.json` | the gate's decision with every finding and its outcome (`fail`, `suppressed`, `below-threshold`, `no-fix-available`) |
| `ci-result-security.json` | the same `ci-result/v1` shape as the test job, for agents |

Kept in git:
- With each environment: `security-record.json`, with the gate summary and the failing and suppressed findings, and `findings-source.json`.
- With each promotion, in `promotions/done/<id>/`: the prod gate's record from when it was applied.

## Not here yet

- **Signing:** `actions/sign` still records `signed: false`. cosign, with the SBOM and scan results attached as attestations, is next. After that, an admission policy can refuse unsigned images in the cluster.
- **A single pane:** Dependency-Track or DefectDojo can read the records as they are.
- **OSCAL:** the records are keyed by commit and digest, with tool versions and file hashes. An OSCAL assessment-results generator lives in its own repo and reads them (decision D-13).
