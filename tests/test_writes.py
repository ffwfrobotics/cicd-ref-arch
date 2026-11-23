"""CI/CD writes only to its own repos (tenants/_writable.yaml): the IaC repos that wrap apps, the platform,
compliance and dashboard repos. A developer's repo is read only, even where the bot has write on it (the
software factory shares the bot account; a user's grant to it is not a grant to CI/CD)."""
import re
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
import cicd  # noqa: E402

# Every place the platform writes to a forge, by file, and where it writes. A new write site changes a
# count here and fails this test until it is added: say which repo it writes and why that repo is CI/CD's.
WRITES = {
    "tools/cicd.py": (12, "dispatches on the platform repo; bump and check-images push and open PRs on the IaC "
                          "root, after writable()"),
    "tools/wrap.py": (6, "creates and pushes the IaC repo in the IaC org; webhooks only where writable()"),
    "tools/stack.py": (2, "deploy keys on a stack's repos, only where writable()"),
    "tools/evidence.py": (4, "releases and assets on the evidence repo (cicd-cluster.yaml evidence)"),
    "tools/intake.py": (2, "commit statuses, posted by the pipeline only when the IaC root is writable"),
    "tools/runtime.py": (2, "the cicd/runtime status, posted by the pipeline only when the IaC root is writable"),
    "tools/enroll.py": (2, "the webhook, with the enrolling admin's own token, on a writable repo only"),
    ".forgejo/workflows/pipeline.yaml": (4, "assess dispatch and stack records on the platform repo; the "
                                            "cicd/stack status only when writable"),
    ".forgejo/workflows/assess.yaml": (1, "the platform repo"),
    ".forgejo/workflows/enroll.yaml": (2, "the tenant record and first run, on the platform repo"),
    ".forgejo/workflows/environments.yaml": (1, "the platform repo"),
    "actions/deploy-env/action.yaml": (1, "the platform repo"),
    "actions/manage-env/action.yaml": (1, "the platform repo"),
    "actions/request-promotion/action.yaml": (4, "the promote/* branch, its PR and its status, on the platform repo"),
}
WRITE = re.compile(r'"(POST|PUT|PATCH|DELETE)"|-X (POST|PUT|PATCH|DELETE)|git[^\n]{0,40}push|/statuses/')


class Writes(unittest.TestCase):
    def test_every_write_site_is_accounted_for(self):
        found = {}
        for pattern in ("tools/*.py", "actions/*/action.yaml", ".forgejo/workflows/*.yaml"):
            for p in sorted(ROOT.glob(pattern)):
                n = len(WRITE.findall(p.read_text()))
                if n:
                    found[str(p.relative_to(ROOT))] = n
        self.assertEqual(found, {k: v[0] for k, v in WRITES.items()},
                         "a forge write was added or removed: update WRITES with where it writes and why that repo is CI/CD's")

    def test_every_iac_root_is_ci_cds(self):
        for name, t in cicd.load_tenants(ROOT).items():
            repo = cicd.tenant_spec(t)["repo"]
            self.assertTrue(cicd.writable(ROOT, repo), f"{name}: its IaC root {repo} is a developer's repo: wrap it")

    def test_writable(self):
        root = Path(tempfile.mkdtemp())
        (root / "tenants").mkdir()
        (root / "tenants/_writable.yaml").write_text("owners: [acme-iac]\nrepos: [acme/cicd-platform]\n")
        self.assertTrue(cicd.writable(root, "acme-iac/anything"))
        self.assertTrue(cicd.writable(root, "acme/cicd-platform"))
        self.assertFalse(cicd.writable(root, "acme/demo-app"))
        self.assertFalse(cicd.writable(root, "acme-fixtures/fx-svc-a"))
        self.assertFalse(cicd.writable(root / "nowhere", "acme-iac/x"))     # no list: nothing is writable

if __name__ == "__main__":
    unittest.main()
