# Continuous self-assessment (OSCAL)

Every build makes an OSCAL **assessment-results** document for its commit: which NIST SP 800-53A objectives the evidence satisfies, and why not where it doesn't. It is the information system owner's **self-assessment** and continuous-monitoring evidence, labelled so in its metadata (`assessment-kind: self-assessment`). Official assessments come from the assessor (the CSPD app). Nothing goes to IT Security automatically: the owner releases packages from the dashboard ([cicd-dashboard](https://forge.goblincorps.com/ffwf/cicd-dashboard)).

Plans: akb #451 and #455. OSCAL 1.2.3, the version of NIST's 800-53 Rev 5.2.0 content. Every document the tools write validates against the OSCAL 1.2.3 JSON schema.

## Where things are

| What | Where |
|---|---|
| Catalog excerpt (800-53 with 800-53A objectives), profiles | compliance repo (`ffwf/cicd-compliance`): `catalogs/`, `profiles/` |
| Layer 1: what the pipeline implements | here: `oscal/platform.yaml` |
| Layer 2: the app's own statements (optional, never required) | app repo: `oscal/component.yaml` |
| Layer 3: the owner's sysadmins (legacy apps, overrides, manual evidence) | compliance repo: `apps/<app>/component.yaml` |
| The app as its owner describes it (profile, impact, release rule, promotion requirement) | compliance repo: `apps/<app>/app.yaml` |
| IT Security's findings | compliance repo: `ledger/<app>.yaml` |
| Announced vulnerabilities | compliance repo: `advisories/<id>.yaml` |
| One commit's evidence and assessment | state repo: `envs/<cluster>/<app>/<env>/evidence/` |

The compliance repo is named in `clusters/<cluster>/cicd-cluster.yaml` (`compliance:`). Without it, builds still run, without IT Security's findings or an assessment.

## Layers and evidence selectors

Layers are merged objective by objective, in order (platform, app, sysadmin); a later layer replaces an earlier one for that objective, and the result records which layer said it. An objective is:
- **automated** when all its evidence is from the pipeline;
- **manual** when some is an attestation;
- **not-applicable** with a reason;
- **uncovered** when no layer says anything (shown, never hidden).

| Selector | Holds when |
|---|---|
| `sbom` | the commit's CycloneDX SBOM has components |
| `scan {tool}` | that scanner produced output for the commit |
| `findings {category}` | no finding in that category (or `all`) would block prod |
| `ci-result {job}` | `test`: the tests passed; `security`: the security job ran |
| `gate` | a gate record exists (every finding has an outcome) |
| `vuln-db {max_age_h}` | grype's database was at most that old at the scan |
| `manifests` | the rendered manifests are kept in git |
| `config-control` | the commit is a full SHA and the image is pinned by digest |
| `release {within_days}` | the owner released a package covering the app to IT Security recently |
| `attested {name, by, at, expires, note}` | someone said so, and it hasn't expired |

```sh
tools/oscal.py component oscal/platform.yaml           # layer 1 as an OSCAL component-definition
tools/oscal.py ssp ... --app-config apps/demo/app.yaml  # the app's SSP (status per control from coverage)
tools/oscal.py assess ... --evidence <dir>              # assessment-results.json + assessment-summary.json
```

## IT Security's findings become failing tests

The owner's sysadmins import IT Security's findings into `ledger/<app>.yaml`, from the dashboard (a Tenable-style CSV) or by hand. Each finding carries a **check** that can be re-run on any commit (`tools/external.py`):

| Check | Fails while |
|---|---|
| `package {name, ecosystem?, affected}` | the commit's SBOM has an affected version (`<25`, `>=2.0,<2.3`) |
| `rule {rule, tool?}` | a scanner reports that rule, even if the developers suppressed it |
| `endpoint {path?, header?, status?, contains?}` | the environment's URL lacks the header or status. Checked through the cluster gateway (`probe.via`), after the deploy has rolled out. |
| `manual` | until someone closes it in the ledger |

- In the gate, each one is a test, `external/<id>`, in the security record, the ci-result record and the run summary. In dev and branch environments it's a warning; in prod it blocks.
- The developers' `policy.yaml` and VEX can't suppress it. Only the owner's security role can, by setting `status: accepted` with `by`, `reason` and `expires`. That acceptance is a claim for the assessor to judge.
- A finding is gone when its check passes, or when someone sets `status: closed`.

```yaml
# ledger/demo.yaml
findings:
- id: ITS-0002
  title: HSTS missing from HTTPS responses
  severity: medium
  check: {type: endpoint, path: /, header: Strict-Transport-Security}
  status: open
  source: {kind: tenable-csv, imported_by: john, imported_at: 2026-11-20T05:00:00Z}
```

## Advisories trigger re-scans of only the affected environments

An advisory (`advisories/<id>.yaml`: `id, title, severity, package {name, ecosystem, affected, fixed}, announced`) is matched against the SBOM every environment keeps. It counts as a vulnerability, like one of grype's: the app's own records may say it isn't affected (an ignore with a reason and an expiry). The dashboard finds which environments' SBOMs match and asks for a re-assessment of just those. A daily run re-scans every kept SBOM with the newest grype database.

## Re-assessment without a rebuild

`.forgejo/workflows/assess.yaml` runs `tools/cicd.py reassess`. For each chosen environment it:
1. re-scans the kept SBOM with grype;
2. re-gates it with IT Security's findings and the advisories as they are now, probing endpoints;
3. re-assesses it;
4. commits the new `security-record.json` and `evidence/`.

It is dispatched by:
- the dashboard, for the affected environments;
- an app's pipeline after a deploy, when the app has endpoint checks (90 s later);
- a daily schedule, for everything.

## The promotion requirement

At request and again at apply, a promotion is re-scanned and gated with IT Security's findings and the advisories; endpoint checks look at the source environment, which runs the same image. The promotion PR shows the self-assessment.

If `apps/<app>/app.yaml` says `promotion.require_assessment: true`, any unsatisfied objective whose failing evidence is a finding, scan, SBOM, test record, gate, database age or expired attestation also refuses the promotion. Uncovered objectives, and a release not made yet, are shown but never block.
