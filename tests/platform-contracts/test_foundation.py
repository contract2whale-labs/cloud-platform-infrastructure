import unittest
from pathlib import Path
import yaml
import copy

ROOT = Path(__file__).resolve().parents[2]

def dns_scope_valid(rule):
    peers = rule["to"]
    intended = next((p for p in peers if "namespaceSelector" in p and "podSelector" in p), None)
    if intended is None:
        return False
    if intended["namespaceSelector"]["matchLabels"].get("kubernetes.io/metadata.name") != "kube-system":
        return False
    if intended["podSelector"]["matchLabels"].get("k8s-app") != "kube-dns":
        return False
    return {(p["protocol"], p["port"]) for p in rule["ports"]} == {("UDP", 53), ("TCP", 53)}

class FoundationContracts(unittest.TestCase):
    def require_authored_stage(self, primary):
        """An unopened course stage has no desired source to validate yet.

        Skip only when its first declaration is absent. Once that declaration
        exists, all supporting files and every contract below must pass.
        """
        if not (ROOT / primary).exists():
            self.skipTest("source stage not authored yet: " + primary)

    def test_cert_manager_identity_and_prerequisites(self):
        self.require_authored_stage("gitops/platform/cert-manager/values/dev.yaml")
        values = yaml.safe_load((ROOT / "gitops/platform/cert-manager/values/dev.yaml").read_text())
        self.assertEqual(values["serviceAccount"]["name"], "cert-manager")
        self.assertEqual(values["serviceAccount"]["annotations"], {})
        self.assertTrue(values["crds"]["enabled"])
        self.assertFalse(values["config"]["gatewayAPI"]["enabled"])
        self.assertFalse(values["prometheus"]["servicemonitor"]["enabled"])
    def test_mesh_namespace_and_controller_isolation(self):
        self.require_authored_stage("gitops/platform/istio-cni/values/dev.yaml")
        values = yaml.safe_load((ROOT / "gitops/platform/istio-cni/values/dev.yaml").read_text())
        self.assertEqual(values["profile"], "ambient")
        self.assertNotIn("platform-gateway", values["excludeNamespaces"])
        self.assertIn("monitoring", values["excludeNamespaces"])
        controller = yaml.safe_load((ROOT / "gitops/platform/istiod/values/dev.yaml").read_text())
        self.assertEqual(controller["pilot"]["env"]["PILOT_ENABLE_GATEWAY_API_DEPLOYMENT_CONTROLLER"], "false")
    def test_dns_policy_does_not_expand_and_keeps_both_transports(self):
        self.require_authored_stage("gitops/platform/network-policy/base/policies.yaml")
        policies = list(yaml.safe_load_all((ROOT / "gitops/platform/network-policy/base/policies.yaml").read_text()))
        dns = next(p for p in policies if p["metadata"]["name"] == "allow-dns")
        rule = dns["spec"]["egress"][0]
        self.assertTrue(dns_scope_valid(rule))
        broadened = copy.deepcopy(rule)
        peer = broadened["to"][0]
        broadened["to"] = [{"namespaceSelector": peer["namespaceSelector"]}, {"podSelector": peer["podSelector"]}]
        self.assertFalse(dns_scope_valid(broadened), "splitting peers turns the intended AND into OR")
        missing_tcp = copy.deepcopy(rule)
        missing_tcp["ports"] = [p for p in missing_tcp["ports"] if p["protocol"] == "UDP"]
        self.assertFalse(dns_scope_valid(missing_tcp), "DNS retry/large-response TCP path must remain allowed")

    def test_mesh_strict_and_identity_rule(self):
        self.require_authored_stage("gitops/platform/mesh-policy/base/peer-authentication.yaml")
        peer = yaml.safe_load((ROOT / "gitops/platform/mesh-policy/base/peer-authentication.yaml").read_text())
        self.assertEqual(peer["spec"]["mtls"]["mode"], "STRICT")
        policies = list(yaml.safe_load_all((ROOT / "gitops/platform/mesh-policy/base/authorization-policy.yaml").read_text()))
        policy = next(p for p in policies if p["metadata"]["name"] == "allow-mesh-client-to-server")
        source = policy["spec"]["rules"][0]["from"][0]["source"]
        self.assertIn("cluster.local/ns/team-mesh-check/sa/mesh-client", source["principals"])
        self.assertEqual(policy["spec"]["rules"][0]["to"][0]["operation"]["ports"], ["8080"])

if __name__ == "__main__":
    unittest.main()
