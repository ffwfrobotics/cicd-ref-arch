"""The stack provider contract (tools/stack.py, docs/stacks.md, akb #493)."""
import ipaddress
import json
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace

import yaml

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "tools"))
import stack  # noqa: E402

HOST = [ipaddress.ip_network("10.244.0.0/16"), ipaddress.ip_network("10.96.0.0/12")]


class Slots(unittest.TestCase):
    def test_ranges_never_overlap(self):
        slots = stack.load_slots(REPO, "c-local")
        nets = HOST[:]
        for s in slots:
            for cidr in (s.pod_cidr, s.svc_cidr):
                n = ipaddress.ip_network(cidr)
                self.assertFalse(any(n.overlaps(m) for m in nets), f"{s.name} {cidr} overlaps")
                nets.append(n)
        self.assertEqual(slots[0].dns_name, "api.stack-slot-1.svc.cluster.local")


class K0sPod(unittest.TestCase):
    def test_manifests_use_the_slot(self):
        s = stack.load_slots(REPO, "c-local")[1]
        req = stack.ClusterRequest(slot=s, name="stack-ref", run="7", fleet_ref="o/r@x:cluster")
        items = json.loads(stack.K0sPod().manifests(req))["items"]
        kinds = {i["kind"]: i for i in items}
        cfg = yaml.safe_load(kinds["ConfigMap"]["data"]["k0s.yaml"])["spec"]
        self.assertEqual((cfg["network"]["podCIDR"], cfg["network"]["serviceCIDR"]), (s.pod_cidr, s.svc_cidr))
        self.assertIn(s.dns_name, cfg["api"]["sans"])
        self.assertEqual(kinds["Service"]["spec"]["ports"][0]["port"], 6443)
        self.assertTrue(kinds["Pod"]["spec"]["containers"][0]["securityContext"]["privileged"])
        self.assertEqual(stack.K0sPod.isolation, "none")


class Check(unittest.TestCase):
    def test_missing_capability_is_not_exercised(self):
        h = stack.ClusterHandle(kubeconfig="x", api_endpoint="https://a", registry="", capabilities=frozenset({"api"}),
                                isolation="none", provider="t@1")
        real = stack.kustomizations
        stack.kustomizations = lambda k: [{"name": "stack", "ready": True}, {"name": "x", "ready": True}]
        try:
            r = stack.check(h, SimpleNamespace(needs=["api", "csi"], timeout=5, min_kustomizations=2))
        finally:
            stack.kustomizations = real
        self.assertEqual((r["result"], r["exercised"], r["not_exercised"]), ("ready", ["api"], ["csi"]))


if __name__ == "__main__":
    unittest.main()


class Config(unittest.TestCase):
    def test_slot_wins_over_the_stack_config(self):
        s = stack.load_slots(REPO, "c-local")[0]
        mine = "apiVersion: k0s.k0sproject.io/v1beta1\nkind: ClusterConfig\nspec:\n  network: {podCIDR: 10.244.0.0/16}\n  api: {sans: [x.example]}\n"
        cfg = yaml.safe_load(stack.K0sPod().k0s_config(s, mine))["spec"]
        self.assertEqual(cfg["network"]["podCIDR"], s.pod_cidr)
        self.assertIn("x.example", cfg["api"]["sans"])
        self.assertIn(s.dns_name, cfg["api"]["sans"])

    def test_smoke_not_exercised_without_the_capability(self):
        h = stack.ClusterHandle("x", "https://a", "", frozenset({"api"}), "none", "t@1")
        self.assertEqual(stack.smoke(h, "true", ["api", "nodes"])["result"], "not-exercised")


class VClusterProvider(unittest.TestCase):
    def test_template_is_namespaced_and_unprivileged(self):
        s = stack.load_slots(REPO, "c-local")[0]
        req = stack.ClusterRequest(slot=s, name="x", run="1", fleet_ref="o/r@x:cluster")
        docs = json.loads(stack.VCluster().manifests(req))["items"]
        self.assertTrue(docs)
        self.assertFalse([d["kind"] for d in docs if d["kind"].startswith("Cluster")])
        self.assertFalse([d for d in docs if d["kind"] == "PersistentVolumeClaim"])
        for d in docs:
            self.assertEqual(d["metadata"].get("namespace", s.name), s.name)
        text = json.dumps(docs)
        self.assertNotIn('"privileged": true', text)
        cfg = next(d for d in docs if d["kind"] == "Secret" and d["metadata"]["name"] == "vc-config-vc")
        self.assertIn(f"vc.{s.name}.svc.cluster.local", cfg["stringData"]["config.yaml"])
        self.assertNotIn("kind: Secret", (REPO / "platform/stacks/providers/vcluster-0.38.0.yaml").read_text())
        self.assertEqual(stack.VCluster.capabilities, frozenset({"api"}))
