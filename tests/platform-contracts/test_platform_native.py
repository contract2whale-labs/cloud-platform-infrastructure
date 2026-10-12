import hashlib
import unittest
from pathlib import Path
import yaml
ROOT=Path(__file__).resolve().parents[2]

def load(path):return yaml.safe_load((ROOT/path).read_text())

class NativeSourceTests(unittest.TestCase):
    def test_policy_adoption_waits_for_manually_gated_controllers(self):
        for env in ('dev','prod'):
            app=load(f'gitops/clusters/{env}/apps/platform.yaml')
            self.assertNotIn('automated',app['spec'].get('syncPolicy',{}))
    def test_generic_tempo_service_account_survives_old_chart_removal(self):
        base=load('gitops/platform/tempo/base/kustomization.yaml')
        self.assertEqual(base['resources'].count('serviceaccount-platform-tempo.yaml'),1)
        for path in (ROOT/'gitops/platform/tempo/overlays').glob('*/values.yaml'):
            account=yaml.safe_load(path.read_text())['serviceAccount']
            self.assertFalse(account['create'])
            self.assertEqual(account['name'],'platform-tempo')
    def test_application_ownership_and_values_references(self):
        for path in (ROOT/"gitops/clusters").glob("*/platform-applications/*.yaml"):
            app=yaml.safe_load(path.read_text())
            with self.subTest(file=path.name):
                self.assertNotIn("automated",app["spec"].get("syncPolicy",{}),"first adoption must not auto prune")
                self.assertNotIn("finalizers",app["metadata"],"cascade deletion must be separately reviewed")
                sources=app["spec"].get("sources",[app["spec"].get("source",{})])
                for source in sources:
                    if source.get("chart"):
                        self.assertFalse(source["repoURL"].startswith("oci://"),"Argo Helm OCI repoURL has no scheme")
                        for value in source.get("helm",{}).get("valueFiles",[]):
                            if value.startswith("$values/"):self.assertTrue((ROOT/value[8:]).exists(),value)
                    elif source.get("path"):
                        self.assertTrue((ROOT/source["path"]).exists(),source["path"])
    def test_fixed_objstore_secret_is_noncredential_generator_exception(self):
        path="gitops/platform/monitoring/overlays/dev/kustomization.yaml"
        if not (ROOT/path).exists():self.skipTest("Thanos source not introduced yet")
        k=load(path);generator=k["secretGenerator"][0]
        self.assertEqual(generator["name"],"thanos-objstore")
        self.assertTrue(generator["options"]["disableNameSuffixHash"])
        self.assertNotIn("generatorOptions",k,"fixed naming must apply only to this API exception")
        config=load("gitops/platform/monitoring/overlays/dev/objstore.yml")["config"]
        self.assertTrue(config["aws_sdk_auth"])
        self.assertFalse({"access_key","secret_key","session_token"}.intersection(config))
    def test_tempo_native_values_and_component_identity_targets(self):
        for path in (ROOT/"gitops/platform/tempo/overlays").glob("*/kustomization.yaml"):
            k=yaml.safe_load(path.read_text());chart=k["helmCharts"][0]
            self.assertEqual(chart["version"],"3.5.1")
            self.assertEqual(chart["valuesFile"],"values.yaml")
            self.assertTrue((path.parent/chart["valuesFile"]).exists())
            self.assertEqual(k.get("resources",[]),[],"shared serviceaccounts belong to tempo-identities")
            patches="\n".join(p["patch"] for p in k["patches"])
            for name in ["platform-tempo-block-builder","platform-tempo-querier","platform-tempo-backend-worker"]:self.assertIn(name,patches)
    def test_agent_correlation_preserves_body_and_error_delivery(self):
        for path in (ROOT/"gitops/platform/collection-agent/values").glob("*.yaml"):
            cfg=yaml.safe_load(path.read_text())["config"]
            operators=cfg["receivers"]["filelog"]["operators"]
            # Correlation fields are introduced with the application logging source.
            if not any(o.get("id")=="commerce-json" for o in operators):continue
            self.assertEqual([o["id"] for o in operators],["container-parser","commerce-json","commerce-trace"])
            self.assertEqual(operators[1]["parse_to"],"attributes")
            self.assertEqual(operators[1]["on_error"],"send");self.assertEqual(operators[2]["on_error"],"send")
            self.assertIn("contract2whale-demo",operators[1]["if"])
            self.assertIn("commerce-web",operators[1]["if"]);self.assertIn("commerce-api",operators[1]["if"])
            self.assertEqual(cfg["receivers"]["filelog"]["storage"],"file_storage/checkpoints")
    def test_gateway_crd_has_one_owner(self):
        for env in ["dev","prod"]:
            base=ROOT/f"gitops/clusters/{env}/platform-applications"
            if not (base/"platform-crds.yaml").exists():continue
            for component in ["aws-load-balancer-controller","envoy-gateway"]:
                app=yaml.safe_load((base/(component+".yaml")).read_text())
                self.assertTrue(app["spec"]["sources"][0]["helm"]["skipCrds"])
    def test_secret_values_have_no_terraform_producer(self):
        for directory in ["terraform/environments/dev/platform/app-auth","modules/queue-managed","modules/delivery"]:
            if not (ROOT/directory).exists():continue
            files=list((ROOT/directory).glob("*.tf"))
            self.assertTrue(files,"introduced module must include real Terraform source")
            for file in files:
                code=file.read_text()
                self.assertNotIn('resource "aws_secretsmanager_secret_version"',code)
                self.assertNotIn('data "aws_secretsmanager_secret_version"',code)

    def test_auth_probe_routes_to_the_real_readiness_handler(self):
        route_path="gitops/apps/commerce-api/base/httproute-auth-check.yaml"
        if not (ROOT/route_path).exists():self.skipTest("application auth probe not introduced yet")
        route=load(route_path);deployment=load("gitops/apps/commerce-api/base/deployment.yaml")
        service=load("gitops/apps/commerce-api/base/service.yaml")
        rule=route["spec"]["rules"][0]
        self.assertEqual(rule["matches"][0]["path"],{"type":"Exact","value":"/platform-auth-check"})
        rewrite=rule["filters"][0]["urlRewrite"]["path"]
        readiness=deployment["spec"]["template"]["spec"]["containers"][0]["readinessProbe"]["httpGet"]["path"]
        self.assertEqual(rewrite,{"type":"ReplaceFullPath","replaceFullPath":readiness})
        self.assertEqual(rule["backendRefs"][0]["port"],service["spec"]["ports"][0]["port"])
        for env in ["dev","prod"]:
            k=load(f"gitops/platform/gateway-auth/overlays/{env}/kustomization.yaml")
            self.assertEqual(k["resources"],["securitypolicy-app-api-jwt.yaml"],"route ownership stays with the application")
