"""hello: the demo app for cicd-ref-arch. Standard library only.

GET /         an HTML page that names the build it is running
GET /healthz  200 "ok" (readiness and liveness)
GET /api/info JSON: version, commit, hostname, uptime, how many requests this pod has served
"""
import json
import os
import socket
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

STARTED = time.time()
COMMIT = os.environ.get("APP_COMMIT", "unknown")
VERSION = "0.1.1"
served = 0


def info() -> dict:
    return {
        "app": "hello",
        "version": VERSION,
        "commit": COMMIT,
        "pod": socket.gethostname(),
        "uptime_s": round(time.time() - STARTED, 1),
        "served": served,
    }


def page(i: dict) -> str:
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>hello {i['version']}</title>
<style>body{{font:16px/1.5 system-ui,sans-serif;max-width:40rem;margin:4rem auto;padding:0 1rem}}
code{{background:#eee;padding:.1rem .3rem;border-radius:3px}}</style></head>
<body><h1>hello</h1>
<p>Version <code>{i['version']}</code>, commit <code>{i['commit']}</code>.</p>
<p>Served by pod <code>{i['pod']}</code>, up {i['uptime_s']} s, request {i['served']} on this pod.</p>
<p>If this pod was scaled to zero, the request you just made woke it.</p>
</body></html>
"""


class Handler(BaseHTTPRequestHandler):
    server_version = "hello"

    def _send(self, code: int, body: str, ctype: str):
        data = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        global served
        if self.path == "/healthz":
            return self._send(200, "ok\n", "text/plain")
        served += 1
        if self.path == "/api/info":
            return self._send(200, json.dumps(info()) + "\n", "application/json")
        if self.path == "/":
            return self._send(200, page(info()), "text/html; charset=utf-8")
        return self._send(404, "not found\n", "text/plain")

    def log_message(self, fmt, *args):  # one line per request, to stdout
        print(f"{self.address_string()} {fmt % args}", flush=True)


def serve(port: int):
    httpd = ThreadingHTTPServer(("", port), Handler)
    print(f"hello {VERSION} ({COMMIT}) listening on :{port}", flush=True)
    httpd.serve_forever()


if __name__ == "__main__":
    serve(int(os.environ.get("PORT", "8080")))
