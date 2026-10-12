"""Regress exact served-CRD gates without a network or Kubernetes credentials."""
import copy
import importlib.util
import unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location("native_schema_checker",ROOT/"automation/check_platform_sources.py")
checker=importlib.util.module_from_spec(spec);spec.loader.exec_module(checker)

class RenderedSchemaTests(unittest.TestCase):
    def setUp(self):
        self.crd={"apiVersion":"apiextensions.k8s.io/v1","kind":"CustomResourceDefinition",
          "metadata":{"name":"certificates.fixture.example"},"spec":{"group":"fixture.example",
          "names":{"kind":"Certificate"},"versions":[{"name":"v1","served":True,
          "schema":{"openAPIV3Schema":{"type":"object","properties":{"spec":{"type":"object",
          "properties":{"dnsNames":{"type":"array","items":{"type":"string"}},
          "optional":{"type":"string","nullable":True},"opaque":{"type":"object",
          "x-kubernetes-preserve-unknown-fields":True}}}}}}}]}}
        self.cert={"apiVersion":"fixture.example/v1","kind":"Certificate","metadata":{"name":"gateway"},
                   "spec":{"dnsNames":["dev.example.invalid"]}}
    def test_single_dns_name_still_requires_an_array(self):
        self.assertEqual(checker.check_crd_schemas([self.crd,self.cert])["crd_objects_checked"],1)
        self.cert["spec"]["dnsNames"]="dev.example.invalid"
        with self.assertRaisesRegex(ValueError,"dnsNames"):checker.check_crd_schemas([self.crd,self.cert])
    def test_unknown_crd_field_is_not_silently_pruned(self):
        self.cert["spec"]["dnsName"]=["dev.example.invalid"]
        with self.assertRaisesRegex(ValueError,"unknown field /spec/dnsName"):checker.check_crd_schemas([self.crd,self.cert])
    def test_missing_crd_is_not_an_ignored_success(self):
        with self.assertRaisesRegex(ValueError,"no matching served CRD"):checker.check_crd_schemas([self.cert])
    def test_unserved_api_version_is_rejected(self):
        self.crd["spec"]["versions"][0]["served"]=False
        with self.assertRaisesRegex(ValueError,"no matching served CRD"):checker.check_crd_schemas([self.crd,self.cert])
    def test_conflicting_schemas_are_rejected(self):
        other=copy.deepcopy(self.crd)
        other["spec"]["versions"][0]["schema"]["openAPIV3Schema"]["properties"]["spec"]["properties"]["dnsNames"]["type"]="string"
        with self.assertRaisesRegex(ValueError,"conflicting served CRD"):checker.check_crd_schemas([self.crd,other,self.cert])
    def test_nullable_and_explicit_preserve_unknown_fields(self):
        self.cert["spec"].update(optional=None,opaque={"vendor-field":"allowed"})
        self.assertEqual(checker.check_crd_schemas([self.crd,self.cert])["crd_objects_checked"],1)
    def test_raw_native_octal_is_read_with_kubernetes_semantics(self):
        raw="apiVersion: v1\nkind: Pod\nmetadata: {name: fixture}\nspec:\n  volumes:\n  - name: credential\n    secret: {secretName: fixture, defaultMode: 0755}\n"
        obj=checker.kubernetes_load_all(raw)[0]
        self.assertEqual(obj["spec"]["volumes"][0]["secret"]["defaultMode"],493)
        result=checker.check_crd_schemas([obj])
        self.assertEqual(result["builtin_objects_not_schema_checked"],1)
        self.assertEqual(result["crd_objects_checked"],0)

if __name__=="__main__":unittest.main()
