# Security slots

Every pipeline run passes through the steps below. In v1 they **report and never block** (`mode: report`). The goal is that choosing a tool later means swapping a command, not redesigning the pipeline.

| Slot | Action | Today | Output (stable shape) | Candidates |
|---|---|---|---|---|
| Dockerfile lint | `actions/scan` | hadolint | `security/hadolint.json`, counted in `summary.json` | Tenable container-definition checks, Checkov, Trivy config |
| SBOM | `actions/sbom` | syft, SPDX JSON from the image's OCI tarball | `security/sbom.spdx.json` | the scanner's own SBOM; attach as an OCI referrer |
| Image scan | `actions/scan` | grype over the SBOM | `security/grype.json`, counted in `summary.json` | Tenable (Nessus / Tenable Cloud Security), Trivy |
| Signature | `actions/sign` | stub: records `signed: false` | `security/signature.json` | cosign: a key held by CI, or keyless through Keycloak |
| Base images | the Dockerfile's `ARG BASE` | upstream images pinned by digest | n/a | a hardened-base pipeline ("Chainguard-style": apko/melange or distroless, rebuilt nightly, signed, SBOM'd) |
| Promotion gate | `environments` workflow | approval and time only | n/a | refuse a promotion whose image is unsigned or has findings over a threshold |

## Turning a slot on

- **`cicd.yaml` `spec.security.mode`:** `report` (the default) or `enforce`.
  - With `enforce`, `actions/scan` fails the job on any hadolint error or on a vulnerability at or above `fail-on` (default `critical`).
- **Records:** every slot writes JSON under `security/`, uploaded as the `deliver` artifact. A promotion gate or an agent reads `summary.json`, never a scanner's native format.

## What is deliberately not here yet

- A decision between Tenable and a home-built hardened-base pipeline.
- Where SBOMs and signatures are stored long-term (OCI referrers next to the image is the likely answer).
- Policy for which findings block a promotion.

None of these blocks the CI/CD work.
