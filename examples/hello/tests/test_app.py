import json
import sys
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import app  # noqa: E402


class HelloTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), app.Handler)
        cls.base = f"http://127.0.0.1:{cls.httpd.server_address[1]}"
        threading.Thread(target=cls.httpd.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()

    def get(self, path):
        with urllib.request.urlopen(self.base + path, timeout=5) as r:
            return r.status, r.headers.get("Content-Type"), r.read().decode()

    def test_healthz(self):
        status, ctype, body = self.get("/healthz")
        self.assertEqual(status, 200)
        self.assertEqual(body, "ok\n")

    def test_info_is_json(self):
        status, ctype, body = self.get("/api/info")
        self.assertEqual(status, 200)
        self.assertTrue(ctype.startswith("application/json"))
        self.assertEqual(json.loads(body)["app"], "hello")

    def test_index_names_the_build(self):
        status, _, body = self.get("/")
        self.assertEqual(status, 200)
        self.assertIn(app.VERSION, body)

    def test_unknown_path_404(self):
        with self.assertRaises(urllib.error.HTTPError) as e:
            self.get("/nope")
        self.assertEqual(e.exception.code, 404)


if __name__ == "__main__":
    unittest.main()
