import base64
import importlib.util
import json
import sys
import subprocess
import unittest
import tempfile
import stat
from unittest.mock import patch
from pathlib import Path
from types import SimpleNamespace
ROOT=Path(__file__).resolve().parents[2]
MODULE=ROOT/"automation/publish_operator_image.py"
if MODULE.exists():
    sys.path.insert(0,str(MODULE.parent))
    import publish_operator_image as publisher

@unittest.skipUnless(MODULE.exists(),"protected operator publication is not introduced yet")
class OperatorPublicationTests(unittest.TestCase):
    def setUp(self):
        self.account="111111111111";self.region="ap-northeast-2";self.revision="b"*40;self.digest="sha256:"+"a"*64
        self.registry=self.account+".dkr.ecr."+self.region+".amazonaws.com"
        self.contract={"account_id":self.account,"region":self.region,"environment":"dev","operator":{"repository_name":"platform/database-operator","repository_url":self.registry+"/platform/database-operator"}}
        self.key="arn:aws:kms:"+self.region+":"+self.account+":key/00000000-0000-4000-8000-000000000000"
        self.delivery={"account_id":self.account,"region":self.region,"environment":"dev","signing_key_arn":self.key,"signing_key_alias":"alias/delivery-signing"}
        self.fail_command=None
        self.sbom_version="SPDX-2.3"
        self.attestation_version="SPDX-2.3"
        self.predicate_type="https://spdx.dev/Document"
        self.attestation_stdout=None
        self.key_metadata={"Arn":self.key,"KeyUsage":"SIGN_VERIFY","KeySpec":"ECC_NIST_P256","KeyState":"Enabled","Enabled":True}
        outer=self
        class SDK:
            def client(self,*args,**kwargs):return self
            def get_caller_identity(self):return {"Account":outer.account}
            def get_authorization_token(self,**kwargs):return {"authorizationData":[{"proxyEndpoint":"https://"+outer.registry,"authorizationToken":base64.b64encode(b"AWS:PRIVATE_REGISTRY_TOKEN").decode()}]}
            def describe_key(self,**kwargs):return {"KeyMetadata":outer.key_metadata}
            def describe_images(self,**kwargs):return {"imageDetails":[{"imageDigest":outer.digest}]}
        self.session=SDK();self.calls=[]
    def fake_run(self,command,**kwargs):
        self.calls.append((command,kwargs))
        if self.fail_command and command[:len(self.fail_command)]==self.fail_command:
            raise subprocess.CalledProcessError(1,command)
        if command[0]=="syft" and self.sbom_version!="missing":
            target=Path(command[command.index("-o")+1].split("=",1)[1])
            target.write_text("broken-json" if self.sbom_version=="malformed" else json.dumps({"spdxVersion":self.sbom_version}))
        if command[:2]==["cosign","verify-attestation"]:
            statement={"_type":"https://in-toto.io/Statement/v0.1","subject":[{"name":self.contract["operator"]["repository_url"],"digest":{"sha256":self.digest[7:]}}],"predicateType":self.predicate_type,"predicate":{"spdxVersion":self.attestation_version}}
            stdout=self.attestation_stdout if self.attestation_stdout is not None else json.dumps({"payload":base64.b64encode(json.dumps(statement).encode()).decode(),"signatures":[{"sig":"VERIFIED_FIXTURE"}]})
            return SimpleNamespace(stdout=stdout,returncode=0)
        return SimpleNamespace(stdout=self.revision+"\n" if "rev-parse" in command else "",returncode=0)
    def test_cross_account_contract_stops_before_build_or_registry_login(self):
        bad={**self.contract,"account_id":"222222222222"}
        with self.assertRaises(ValueError):publisher.publish(bad,self.delivery,self.account,self.region,"dev",self.revision,ROOT,self.session,self.fake_run)
        self.assertEqual(self.calls,[])
    def test_public_receipt_has_no_token_and_login_uses_isolated_stdin(self):
        result=publisher.publish(self.contract,self.delivery,self.account,self.region,"dev",self.revision,ROOT,self.session,self.fake_run)
        self.assertEqual(result["operator_image_digest"],self.digest)
        self.assertNotIn("PRIVATE_REGISTRY_TOKEN",json.dumps(result))
        login=next((cmd,kw) for cmd,kw in self.calls if cmd[:2]==["docker","login"])
        self.assertNotIn("PRIVATE_REGISTRY_TOKEN",json.dumps(login[0]))
        self.assertEqual(login[1]["input"],"PRIVATE_REGISTRY_TOKEN")
        self.assertFalse(Path(login[1]["env"]["DOCKER_CONFIG"]).exists(),"temporary registry credentials are cleaned up")

    def test_sign_and_spdx_attestation_precede_both_verifications(self):
        result=publisher.publish(self.contract,self.delivery,self.account,self.region,"dev",self.revision,ROOT,self.session,self.fake_run)
        commands=[command for command,_ in self.calls]
        relevant=[command for command in commands if command[0] in {"syft","cosign"}]
        self.assertEqual([command[:2] for command in relevant],[["syft",self.contract["operator"]["repository_url"]+"@"+self.digest],["cosign","sign"],["cosign","attest"],["cosign","verify"],["cosign","verify-attestation"]])
        self.assertTrue(result["signature_verified"] and result["spdx_attestation_verified"])
        for command in relevant[1:3]:
            self.assertIn("--use-signing-config=false",command)
            self.assertIn("--new-bundle-format=false",command)
        self.assertIn("spdxjson",relevant[2])

    def test_each_artifact_failure_returns_no_receipt_and_logs_out(self):
        for command in (["syft"],["cosign","sign"],["cosign","attest"],["cosign","verify"],["cosign","verify-attestation"]):
            with self.subTest(command=command):
                self.calls=[];self.fail_command=command
                with self.assertRaises(subprocess.CalledProcessError):
                    publisher.publish(self.contract,self.delivery,self.account,self.region,"dev",self.revision,ROOT,self.session,self.fake_run)
                self.assertEqual(self.calls[-1][0][:2],["docker","logout"])

    def test_wrong_alias_target_or_disabled_key_stops_before_build(self):
        for change in ({"Arn":self.key.replace(self.account,"222222222222")},{"Enabled":False},{"KeyUsage":"ENCRYPT_DECRYPT"},{"KeySpec":"RSA_2048"},{"KeyState":"PendingDeletion"}):
            with self.subTest(change=change):
                self.calls=[]
                self.key_metadata={"Arn":self.key,"KeyUsage":"SIGN_VERIFY","KeySpec":"ECC_NIST_P256","KeyState":"Enabled","Enabled":True,**change}
                with self.assertRaises(ValueError):
                    publisher.publish(self.contract,self.delivery,self.account,self.region,"dev",self.revision,ROOT,self.session,self.fake_run)
                self.assertFalse(any(command[0] in {"bash","docker","syft","cosign"} for command,_ in self.calls))

    def test_unsigned_or_missing_spdx_existing_digest_yields_no_tfvars(self):
        from verify_operator_image import verify
        for command in (["cosign","verify"],["cosign","verify-attestation"]):
            with self.subTest(command=command):
                self.calls=[];self.fail_command=command
                with self.assertRaises(subprocess.CalledProcessError):
                    verify(self.contract,self.delivery,self.account,self.region,"dev",self.digest,self.session,self.fake_run)
                self.assertEqual(self.calls[-1][0][:2],["docker","logout"])

    def test_missing_malformed_or_old_generated_sbom_stops_before_signing(self):
        for version in ("missing","malformed","SPDX-2.2"):
            with self.subTest(version=version):
                self.calls=[];self.sbom_version=version
                with self.assertRaises((ValueError,FileNotFoundError)):
                    publisher.publish(self.contract,self.delivery,self.account,self.region,"dev",self.revision,ROOT,self.session,self.fake_run)
                self.assertFalse(any(command[:2]==["cosign","sign"] for command,_ in self.calls))

    def test_verified_old_wrong_or_malformed_predicate_is_rejected(self):
        from verify_operator_image import verify
        cases=[{"attestation_version":"SPDX-2.2"},{"predicate_type":"https://example.invalid/other"},{"attestation_stdout":""},{"attestation_stdout":"not-json"},{"attestation_stdout":json.dumps({"payload":"not-base64"})}]
        for change in cases:
            with self.subTest(change=change):
                self.calls=[];self.attestation_version="SPDX-2.3";self.predicate_type="https://spdx.dev/Document";self.attestation_stdout=None
                for key,value in change.items():setattr(self,key,value)
                with self.assertRaises(ValueError):
                    verify(self.contract,self.delivery,self.account,self.region,"dev",self.digest,self.session,self.fake_run)
                self.assertEqual(self.calls[-1][0][:2],["docker","logout"])

    def test_verified_envelope_object_and_json_lines_match_exact_subject(self):
        from verify_operator_image import require_spdx23_attestation
        statement={"predicateType":"https://spdx.dev/Document","predicate":{"spdxVersion":"SPDX-2.3"},"subject":[{"digest":{"sha256":self.digest[7:]}}]}
        envelope=json.dumps({"payload":base64.b64encode(json.dumps(statement).encode()).decode()})
        require_spdx23_attestation(envelope,self.digest)
        require_spdx23_attestation(envelope+"\n"+envelope,self.digest)
        with self.assertRaises(ValueError):require_spdx23_attestation(envelope,"sha256:"+"c"*64)
        with self.assertRaises(ValueError):require_spdx23_attestation("["+envelope+"]",self.digest)

    def cli(self, mode, output, collision=False):
        import verify_operator_image as verifier
        module = publisher if mode == "publish" else verifier
        operation = publisher.publish if mode == "publish" else verifier.verify
        contract_reads = []
        def read(repo, environment, root, name):
            contract_reads.append(root)
            return self.contract if root == "data" else self.delivery
        def execute(*args):
            # Keep verify's authenticated recursive call bound to the actual implementation.
            with patch.object(verifier, "verify", verifier.verify if mode == "publish" else operation):
                result = operation(*args, run=self.fake_run)
            if collision:
                output.write_text("late competing output")
            return result
        arguments = ["operator-fixture", "--environment", "dev", "--expect-account", self.account,
                     "--region", self.region]
        if mode == "publish":
            arguments += ["--approved-revision", self.revision, "--receipt", str(output)]
        else:
            arguments += ["--digest", self.digest, "--tfvars", str(output)]
        fake_sdk = SimpleNamespace(Session=lambda: self.session)
        with patch.object(sys, "argv", arguments), patch.dict(sys.modules, {"boto3": fake_sdk}), \
             patch.object(module, "read_contract", side_effect=read), \
             patch.object(module, "publish" if mode == "publish" else "verify", side_effect=execute):
            module.main()
        return contract_reads

    def test_cli_existing_and_broken_symlink_stop_before_sdk_or_subprocess(self):
        for mode in ("publish", "verify"):
            for kind in ("file", "broken-symlink"):
                with self.subTest(mode=mode, kind=kind), tempfile.TemporaryDirectory() as directory:
                    import verify_operator_image as verifier
                    module = publisher if mode == "publish" else verifier
                    output = Path(directory) / "output.json"
                    if kind == "file": output.write_text("original approved output")
                    else: output.symlink_to("absent-target")
                    self.calls = []
                    with patch.object(module, "read_contract", side_effect=AssertionError("contract subprocess ran")), \
                         patch.dict(sys.modules, {"boto3": SimpleNamespace(Session=lambda: self.fail("SDK ran"))}):
                        # The CLI preflight must stop before even the contract output subprocess.
                        arguments = ["fixture", "--environment", "dev", "--expect-account", self.account, "--region", self.region]
                        arguments += (["--approved-revision", self.revision, "--receipt", str(output)] if mode == "publish"
                                      else ["--digest", self.digest, "--tfvars", str(output)])
                        with patch.object(sys, "argv", arguments), self.assertRaises(FileExistsError): module.main()
                    self.assertEqual(self.calls, [])
                    if kind == "file": self.assertEqual(output.read_text(), "original approved output")
                    else: self.assertTrue(output.is_symlink())

    def test_cli_fresh_outputs_are_private_and_keep_business_verification(self):
        for mode in ("publish", "verify"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                output = Path(directory) / "protected" / "output.json"
                self.calls = []
                self.assertEqual(self.cli(mode, output), ["data", "delivery"])
                self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
                result = json.loads(output.read_text())
                self.assertEqual(result["operator_image_digest"], self.digest)
                self.assertNotIn("PRIVATE_REGISTRY_TOKEN", output.read_text())
                self.assertTrue(any(command[:2] == ["cosign", "verify-attestation"] for command, _ in self.calls))

    def test_cli_late_collision_preserves_competing_output(self):
        for mode in ("publish", "verify"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                output = Path(directory) / "output.json"
                self.calls = []
                with self.assertRaises(FileExistsError): self.cli(mode, output, collision=True)
                self.assertEqual(output.read_text(), "late competing output")
                self.assertTrue(any(command[:2] == ["cosign", "verify-attestation"] for command, _ in self.calls))
