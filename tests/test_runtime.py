"""Unit tests for tools/runtime.py's classifier (no cluster). Run: python3 -m unittest -v"""
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "tools"))
import intake   # noqa: E402
import runtime  # noqa: E402


def pod(name="app-1", ready=False, waiting=None, terminated=None, last=None, restarts=0, msg=""):
    st = {}
    if waiting:
        st["waiting"] = {"reason": waiting, "message": msg}
    if terminated:
        st["terminated"] = terminated
    return {"metadata": {"name": name},
            "status": {"phase": "Running", "conditions": [{"type": "Ready", "status": "True" if ready else "False"}],
                       "containerStatuses": [{"name": "app", "ready": ready, "restartCount": restarts, "state": st,
                                              "lastState": {"terminated": last} if last else {}}]}}


def obs(pods=(), events=(), http=None, logs=None, applied=True, elapsed=10, stz=True):
    return {"applied": applied, "pods": list(pods), "events": list(events), "http": http, "logs": logs or {},
            "host": "x.example", "scale_to_zero": stz, "elapsed": elapsed}


def cls(o, final=True):
    r = runtime.classify(o, final)
    return r and r["class"]


class Classify(unittest.TestCase):
    def test_running(self):
        self.assertEqual(cls(obs([pod(ready=True)], http={"status": 200}), final=False), "running")

    def test_waits_while_starting(self):
        self.assertIsNone(cls(obs([pod()]), final=False))
        self.assertIsNone(cls(obs([pod(ready=True)]), final=False))   # ready, the request still out

    def test_image_pull(self):
        self.assertEqual(cls(obs([pod(waiting="ImagePullBackOff", msg="not found")]), final=False), "image-pull")

    def test_crash_with_exit_code(self):
        r = runtime.classify(obs([pod(waiting="CrashLoopBackOff", last={"exitCode": 3, "reason": "Error"}, restarts=2)]), False)
        self.assertEqual((r["class"], r["exit_code"]), ("crash", 3))

    def test_one_restart_then_ready_is_not_a_crash(self):
        self.assertEqual(cls(obs([pod(ready=True, last={"exitCode": 1}, restarts=1)], http={"status": 200})), "running")

    def test_oom(self):
        self.assertEqual(cls(obs([pod(waiting="CrashLoopBackOff", last={"reason": "OOMKilled", "exitCode": 137})]), False), "oom")

    def test_rejected_by_pod_security(self):
        e = {"reason": "FailedCreate", "message": 'pods "a" is forbidden: violates PodSecurity "restricted:latest": runAsNonRoot != true'}
        r = runtime.classify(obs(events=[e]), False)
        self.assertEqual((r["class"], r["detail"]), ("rejected", "runAsNonRoot != true"))

    def test_config_error(self):
        self.assertEqual(cls(obs([pod(waiting="CreateContainerConfigError", msg='secret "db" not found')]), False), "config")

    def test_not_ready_then_localhost(self):
        probe = {"reason": "Unhealthy", "message": 'Readiness probe failed: dial tcp 10.0.0.5:8080: connect: connection refused'}
        self.assertIsNone(cls(obs([pod()], [probe]), final=False))
        self.assertEqual(cls(obs([pod()], [probe])), "not-ready")
        self.assertEqual(cls(obs([pod()], [probe], logs={"a": "Listening on http://127.0.0.1:8080\n"})), "localhost")

    def test_ready_but_5xx_or_unreachable(self):
        self.assertEqual(cls(obs([pod(ready=True)], http={"status": 502})), "http-error")
        self.assertEqual(cls(obs([pod(ready=True)], http={"error": "timeout"})), "unreachable")
        self.assertIsNone(cls(obs([pod(ready=True)], http={"status": 502}), final=False))   # may still recover

    def test_nothing_started(self):
        self.assertEqual(cls(obs(http={"error": "502"})), "not-started")

    def test_not_applied(self):
        self.assertEqual(cls(obs(applied=False)), "not-applied")

    def test_unschedulable_after_30s(self):
        e = {"reason": "FailedScheduling", "message": "0/1 nodes are available: 1 Insufficient memory."}
        p = pod()
        p["status"]["containerStatuses"] = []
        self.assertIsNone(cls(obs([p], [e], elapsed=10), final=False))
        self.assertEqual(cls(obs([p], [e], elapsed=40), final=False), "unschedulable")

    def test_every_class_is_in_the_contract(self):
        ids = {c["id"] for c in intake.contract()["runtime"]}
        src = (REPO / "tools/runtime.py").read_text()
        import re
        used = set(re.findall(r'out\("([a-z-]+)"', src))
        self.assertEqual(used, ids)
        for c in intake.contract()["runtime"]:
            self.assertIn(c["state"], runtime.STATE)

    def test_summary(self):
        v = runtime.verdict({"class": "crash", "detail": "app: exits 1"})
        self.assertEqual(runtime.summary(v).split(".")[0], "crash (app: exits 1)")
        self.assertEqual(runtime.summary(runtime.verdict({"class": "running", "detail": "answers 200"})), "running: answers 200")


if __name__ == "__main__":
    unittest.main()
