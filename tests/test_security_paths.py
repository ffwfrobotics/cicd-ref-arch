"""Finding locations are named from the app's root, wherever the runner checked the app out."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))
import security  # noqa: E402


class AppRelative(unittest.TestCase):
    def test_platform_checkout_under_app(self):
        ws = Path("/w"); app = ws / "app"
        self.assertEqual(security.app_relative("app/Dockerfile:7", app, ws), "Dockerfile:7")
        self.assertEqual(security.app_relative("/w/app/src/x.py:3", app, ws), "src/x.py:3")
        self.assertEqual(security.app_relative("build/app.yaml:13", app, ws), "build/app.yaml:13")

    def test_app_at_root_is_unchanged(self):
        self.assertEqual(security.app_relative("Dockerfile:7", Path("/w"), Path("/w")), "Dockerfile:7")

    def test_suppression_path_matches(self):
        f = {"category": "config", "rule": "CKV_DOCKER_7", "location": security.app_relative("app/Dockerfile:7", Path("/w/app"), Path("/w"))}
        import fnmatch
        self.assertTrue(fnmatch.fnmatch(f["location"], "Dockerfile:*"))


if __name__ == "__main__":
    unittest.main()
