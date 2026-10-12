import copy
import importlib.util
import json
import sys
import tempfile
import stat
from unittest.mock import patch
import unittest
from pathlib import Path
ROOT = Path(__file__).resolve().parents[2]
MODULE = ROOT / "automation/secrets/provision.py"
if MODULE.exists():
    sys.path.insert(0, str(MODULE.parent))
    import provision as producer
    import verify_receipt as verifier

class FakeSTS:
    def __init__(self, account="111111111111"): self.account=account
    def get_caller_identity(self): return {"Account":self.account}
class FakeSecrets:
    def __init__(self): self.versions={};self.writes=[]
    def get_paginator(self, operation): return self
    def paginate(self, SecretId, IncludeDeprecated):
        yield {"Versions":[{"VersionId":v,"VersionStages":stages} for v,stages in self.versions.get(SecretId,{}).items()]}
    def describe_secret(self, SecretId):
        return {"ARN":SecretId,"Name":SecretId.split(":secret:")[1],"KmsKeyId":"arn:aws:kms:ap-northeast-2:111111111111:key/test", "VersionIdsToStages":self.versions.get(SecretId,{})}
    def put_secret_value(self, **kwargs):
        self.writes.append(kwargs)
        for stages in self.versions.setdefault(kwargs["SecretId"],{}).values():
            if "AWSCURRENT" in stages: stages.remove("AWSCURRENT")
        self.versions[kwargs["SecretId"]][kwargs["ClientRequestToken"]]=["AWSCURRENT"]
class FakeCognito:
    def __init__(self): self.clients=[];self.calls=[]
    def list_user_pool_clients(self, **kw):return {"UserPoolClients":self.clients}
    def create_user_pool_client(self, **kw):
        self.calls.append(kw)
        client={**kw,"ClientId":"fixture-client-id","ClientSecret":"PRIVATE_CLIENT_SECRET"}
        self.clients.append(client)
        return {"UserPoolClient":client}
    def describe_user_pool_client(self, **kw):return {"UserPoolClient":self.clients[0]}
class FakeSession:
    def __init__(self, account="111111111111"):
        self.sts=FakeSTS(account);self.sm=FakeSecrets();self.cognito=FakeCognito()
    def client(self, name, **kw):return {"sts":self.sts,"secretsmanager":self.sm,"cognito-idp":self.cognito}[name]

@unittest.skipUnless(MODULE.exists(), "credential producer is introduced in a later source change")
class ProtectedProducerTests(unittest.TestCase):
    def request(self, kind="queue-scram"):
        r={"schema_version":1,"request_id":"approved-request-001","account_id":"111111111111","environment":"dev","region":"ap-northeast-2","operation":kind}
        arn="arn:aws:secretsmanager:ap-northeast-2:111111111111:secret:AmazonMSK_test-"
        if kind=="queue-scram":r["users"]={p:{"secret_arn":arn+p,"username":p} for p in ["writer","reader"]}
        else:r.update(user_pool_id="ap-northeast-2_fixture",client_name="automation",secret_arn=arn+"cognito",scopes=["platform/probe"],token_endpoint="https://fixture.example/oauth2/token",callback_urls=[])
        return producer.validate(r,r["account_id"],"dev")
    def test_same_request_retry_does_not_generate_new_version(self):
        s=FakeSession();r=self.request();first=producer.execute(r,s);second=producer.execute(r,s)
        self.assertEqual(first,second);self.assertEqual(len(s.sm.writes),2)
        payload=json.dumps(first)
        for write in s.sm.writes:self.assertNotIn(json.loads(write["SecretString"])["password"],payload)
        self.assertNotIn("password",payload);self.assertNotIn("SecretString",payload)
    def test_changed_payload_cannot_reuse_old_receipt(self):
        for field in ["username", "secret_arn"]:
            with self.subTest(field=field):
                s=FakeSession();r=self.request();receipt=producer.execute(r,s)
                changed=copy.deepcopy(r)
                changed["users"]["writer"][field]+="-changed"
                self.assertNotEqual(producer.token(r,"writer"),producer.token(changed,"writer"))
                with self.assertRaises(ValueError):verifier.verify(changed,receipt,s)
                self.assertEqual(len(s.sm.writes),2)
        r=self.request("cognito-verifier")
        for field in ["token_endpoint", "scopes", "secret_arn"]:
            with self.subTest(field=field):
                changed=copy.deepcopy(r)
                changed[field]=["platform/other"] if field=="scopes" else changed[field]+"-changed"
                self.assertNotEqual(producer.token(r,"cognito-client"),producer.token(changed,"cognito-client"))
        reordered=dict(reversed(list(r.items())))
        self.assertEqual(producer.token(r,"cognito-client"),producer.token(reordered,"cognito-client"))
    def test_later_rotation_cannot_be_reverted_by_retry(self):
        s=FakeSession();r=self.request();producer.execute(r,s)
        s.sm.versions[r["users"]["writer"]["secret_arn"]][producer.token(r,"writer")]=["AWSPREVIOUS"]
        with self.assertRaises(ValueError):producer.execute(r,s)
        self.assertEqual(len(s.sm.writes),2)
    def test_wrong_authenticated_account_performs_no_write(self):
        s=FakeSession("222222222222")
        with self.assertRaises(ValueError):producer.execute(self.request(),s)
        self.assertEqual(s.sm.writes,[])
    def test_credential_fields_and_cross_account_arn_rejected(self):
        r=self.request();r["password"]="NEVER_ACCEPT"
        with self.assertRaises(ValueError):producer.validate(r,r["account_id"],"dev")
        r=self.request();r["users"]["reader"]["secret_arn"]=r["users"]["reader"]["secret_arn"].replace("111111111111","222222222222")
        with self.assertRaises(ValueError):producer.validate(r,r["account_id"],"dev")
    def test_confidential_client_created_outside_state_and_receipt_has_no_secret(self):
        s=FakeSession();r=self.request("cognito-verifier");receipt=producer.execute(r,s)
        self.assertTrue(s.cognito.calls[0]["GenerateSecret"])
        self.assertEqual(s.cognito.calls[0]["AllowedOAuthFlows"],["client_credentials"])
        self.assertNotIn("CallbackURLs",s.cognito.calls[0])
        self.assertNotIn("PRIVATE_CLIENT_SECRET",json.dumps(receipt))
        self.assertEqual(producer.execute(r,s),receipt);self.assertEqual(len(s.cognito.calls),1)
    def test_verifier_rejects_openid_and_callbacks(self):
        r=self.request("cognito-verifier");r["scopes"]=["openid"]
        with self.assertRaises(ValueError):producer.validate(r,r["account_id"],"dev")
    def test_metadata_verification_rejects_stale_and_forged_receipt(self):
        s=FakeSession();r=self.request();receipt=producer.execute(r,s)
        result=verifier.verify(r,receipt,s)
        self.assertEqual(result["credentials_receipt"]["request_id"],r["request_id"])
        self.assertNotIn("password",json.dumps(result))
        forged=copy.deepcopy(receipt);forged["secret_version_ids"]["reader"]="fake"
        with self.assertRaises(ValueError):verifier.verify(r,forged,s)
        s.sm.versions[r["users"]["reader"]["secret_arn"]][producer.token(r,"reader")]=["AWSPREVIOUS"]
        with self.assertRaises(ValueError):verifier.verify(r,receipt,s)

    def test_cognito_receipt_passes_only_public_client_id_to_terraform(self):
        s=FakeSession();r=self.request("cognito-verifier");receipt=producer.execute(r,s)
        result=verifier.verify(r,receipt,s)
        self.assertEqual(result,{"verifier_client_id":"fixture-client-id"})
        self.assertNotIn("PRIVATE_CLIENT_SECRET",json.dumps(result))
        forged=copy.deepcopy(receipt);forged["client_id"]="another-client"
        with self.assertRaises(ValueError):verifier.verify(r,forged,s)
        s.sm.versions[r["secret_arn"]][receipt["secret_version_id"]]=["AWSPREVIOUS"]
        with self.assertRaises(ValueError):verifier.verify(r,receipt,s)


class ReceiptPathTests(unittest.TestCase):
    def test_existing_receipt_stops_before_execute(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory).resolve(); receipt=root/"receipt.json"; receipt.write_text("previous")
            request=root/"request.json"
            fixture=ProtectedProducerTests().request()
            request.write_text(json.dumps(fixture))
            argv=["provision", "--request", str(request), "--expect-account", fixture["account_id"], "--expect-environment", "dev", "--receipt", str(receipt)]
            with patch.object(sys,"argv",argv), patch.object(producer,"execute") as execute:
                with self.assertRaises(ValueError):producer.main()
                execute.assert_not_called()
            self.assertEqual(receipt.read_text(),"previous")
    def test_dangling_receipt_stops_early(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory).resolve(); receipt=root/"receipt.json"; receipt.symlink_to(root/"absent")
            with self.assertRaises(ValueError):producer.prepare_receipt(receipt)
            self.assertFalse((root/"absent").exists())
    def test_late_collision_preserves_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            receipt=Path(directory).resolve()/"receipt.json"
            producer.prepare_receipt(receipt); receipt.write_text("concurrent")
            with self.assertRaises(FileExistsError):producer.write_receipt(receipt,{"client_id":"public"})
            self.assertEqual(receipt.read_text(),"concurrent")
    def test_new_receipt_mode_and_metadata(self):
        with tempfile.TemporaryDirectory() as directory:
            receipt=Path(directory).resolve()/"receipt.json"
            producer.prepare_receipt(receipt); producer.write_receipt(receipt,{"client_id":"public"})
            self.assertEqual(json.loads(receipt.read_text()),{"client_id":"public"})
            self.assertEqual(stat.S_IMODE(receipt.stat().st_mode),0o600)


class VerificationOutputTests(unittest.TestCase):
    def test_existing_output_stops_before_sdk_import(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory).resolve(); output=root/"approved.json"; output.write_text("previous")
            request=root/"request.json"; receipt=root/"receipt.json"
            fixture=ProtectedProducerTests().request(); request.write_text(json.dumps(fixture)); receipt.write_text("{}")
            argv=["verify_receipt", "--request", str(request), "--receipt", str(receipt), "--expect-account", fixture["account_id"], "--expect-environment", "dev", "--tfvars", str(output)]
            with patch.object(sys,"argv",argv), patch.object(verifier,"verify") as verify, patch.dict(sys.modules,{"boto3":None}):
                with self.assertRaises(FileExistsError):verifier.main()
                verify.assert_not_called()
            self.assertEqual(output.read_text(),"previous")
    def test_broken_link_is_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory).resolve(); output=root/"approved.json"; output.symlink_to(root/"absent")
            with self.assertRaises(FileExistsError):verifier.prepare_output(output)
            self.assertTrue(output.is_symlink()); self.assertFalse((root/"absent").exists())
    def test_parent_link_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory).resolve(); target=root/"real"; target.mkdir(); link=root/"link"; link.symlink_to(target,target_is_directory=True)
            with self.assertRaises(ValueError):verifier.prepare_output(link/"approved.json")
            self.assertFalse((target/"approved.json").exists())
    def test_late_collision_preserves_output(self):
        with tempfile.TemporaryDirectory() as directory:
            output=Path(directory).resolve()/"approved.json"
            verifier.prepare_output(output); output.write_text("concurrent")
            with self.assertRaises(FileExistsError):verifier.write_output(output,{"argocd_oidc_client_id":"public"})
            self.assertEqual(output.read_text(),"concurrent")
    def test_new_output_has_exact_mode_and_public_metadata(self):
        with tempfile.TemporaryDirectory() as directory:
            output=Path(directory).resolve()/"approved.json"
            verifier.prepare_output(output); verifier.write_output(output,{"argocd_oidc_client_id":"public"})
            self.assertEqual(stat.S_IMODE(output.stat().st_mode),0o600)
            self.assertEqual(json.loads(output.read_text()),{"argocd_oidc_client_id":"public"})
