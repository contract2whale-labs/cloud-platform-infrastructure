import copy,importlib.util,json,pathlib,tempfile,unittest
BASE=pathlib.Path(__file__).resolve().parents[1]
s=importlib.util.spec_from_file_location('bucket_access',BASE/'access.py');m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
FIELDS=('state_kms_arn','evidence_kms_arn','operator_evidence_kms_arn')

class BucketEncryption(unittest.TestCase):
    def config(self):return json.loads((BASE/'examples/dev.json').read_bytes())
    def test_explicit_aes256_requires_no_s3_kms_grant(self):
        c=self.config();c.update({field:None for field in FIELDS});m.validate(c)
        for role in m.ROLES:
            statements=[s for rows in m.policies(c,role).values() for s in rows]
            self.assertFalse(any(s['Sid'].startswith('PrivateS3Encryption') for s in statements))
            self.assertFalse(any(value is None for s in statements for value in s.get('Resource',s.get('NotResource',[]))))
            if role!='lifecycle-destroy':
                inspect=next(s for s in statements if s['Sid']=='InspectPrivateEvidenceBuckets')
                self.assertIn('s3:GetEncryptionConfiguration',inspect['Action'])
        self.assertFalse(any(s['Sid']=='DecryptPrivateProbeBinding' for s in m.aws_fixed_bridge(c)))
        with tempfile.TemporaryDirectory() as directory:
            m.write(c,directory)
            for path in pathlib.Path(directory,'identity','operations-policies').glob('*.json'):
                self.assertNotIn(None,[resource for statement in json.loads(path.read_text())['Statement'] for resource in statement.get('Resource',statement.get('NotResource',[]))])
    def test_mixed_aes256_cmk_grants_only_actual_bucket_and_key(self):
        c=self.config();key=c['evidence_kms_arn'];c.update(state_kms_arn=None,operator_evidence_kms_arn=None,operator_evidence_bucket='separate-aes-evidence');m.validate(c)
        rows=m.policies(c,'gitops-bootstrap')['evidence'];kms=[row for row in rows if row['Sid'].startswith('PrivateS3Encryption')]
        self.assertEqual(len(kms),1);self.assertEqual(kms[0]['Resource'],[key])
        self.assertEqual(kms[0]['Condition']['StringLike']['kms:EncryptionContext:aws:s3:arn'],['arn:aws:s3:::'+c['evidence_bucket'],'arn:aws:s3:::'+c['evidence_bucket']+'/*'])
        self.assertEqual(kms[0]['Condition']['StringEquals']['kms:CallerAccount'],c['account_id'])
        self.assertFalse(any(row['Sid']=='DecryptPrivateProbeBinding' for row in m.aws_fixed_bridge(c)))
    def test_same_cmk_and_bucket_is_deduplicated_and_state_bridge_stays_exact(self):
        c=self.config();m.validate(c)
        kms=[r for r in m.policies(c,'gitops-bootstrap')['evidence'] if r['Sid'].startswith('PrivateS3Encryption')]
        self.assertEqual(len(kms),2)
        bridge=next(r for r in m.aws_fixed_bridge(c) if r['Sid']=='DecryptPrivateProbeBinding')
        self.assertEqual(bridge['Resource'],[c['state_kms_arn']])
    def test_omitted_empty_foreign_or_inconsistent_encryption_rejected(self):
        for field in FIELDS:
            c=self.config();del c[field]
            with self.assertRaises(ValueError):m.validate(c)
            for value in ('','*',False,'arn:aws:kms:ap-northeast-2:222222222222:key/foreign','arn:aws:kms:us-east-1:111111111111:key/wrong-region'):
                c=self.config();c[field]=value
                with self.subTest(field=field,value=value),self.assertRaises(ValueError):m.validate(c)
        c=self.config();c['operator_evidence_kms_arn']=None
        with self.assertRaisesRegex(ValueError,'same actual bucket'):m.validate(c)

if __name__=='__main__':unittest.main()
