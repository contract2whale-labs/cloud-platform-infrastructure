import copy, importlib.util, json, shutil, subprocess, tempfile, unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('publisher',ROOT/'automation/platform_inputs.py');module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)

class PublisherTests(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.repo=Path(self.temp.name).resolve()
  subprocess.run(['git','init','-q',str(self.repo)],check=True)
  subprocess.run(['git','-C',str(self.repo),'config','user.name','Fixture'],check=True);subprocess.run(['git','-C',str(self.repo),'config','user.email','fixture@example.invalid'],check=True)
  subprocess.run(['git','-C',str(self.repo),'commit','--allow-empty','-qm','fixture'],check=True)
  self.sha=subprocess.check_output(['git','-C',str(self.repo),'rev-parse','HEAD'],text=True).strip()
  for d in ['schemas','automation','gitops/platform/monitoring/overlays/dev']:(self.repo/d).mkdir(parents=True,exist_ok=True)
  shutil.copy2(ROOT/'schemas/platform-inputs.schema.json',self.repo/'schemas/platform-inputs.schema.json')
  self.file=self.repo/'gitops/platform/monitoring/overlays/dev/objstore.yml'
  self.file.write_text('# keep the Pod Identity explanation\nconfig:\n  bucket: old-bucket\n  aws_sdk_auth: true\n')
  self.mapping=[{'root':'observability','field':'metrics_bucket','type':'bucket','targets':[{'file':'gitops/platform/monitoring/overlays/{environment}/objstore.yml','pointer':'/config/bucket'}]}]
  self.save_mapping()
  self.request={'schema_version':1,'environment':'dev','account_id':'111111111111','region':'ap-northeast-2','root':'observability','apply_revision':self.sha,'base_revision':self.sha,'state_lineage':'12345678-1234-1234-1234-123456789012','state_serial':12,'values':{'metrics_bucket':'team-dev-metrics-111111111111'}}
 def save_mapping(self):(self.repo/'automation/platform-input-mappings.json').write_text(json.dumps(self.mapping))
 def tearDown(self):self.temp.cleanup()
 def run_request(self):return module.run(self.request,self.repo,'dev','111111111111',self.sha)
 def test_updates_only_reviewed_field_and_preserves_comment(self):
  self.assertTrue(self.run_request());text=self.file.read_text();self.assertIn('# keep the Pod Identity explanation',text);self.assertIn('aws_sdk_auth: true',text);self.assertIn('team-dev-metrics',text)
 def test_application_hostname_updates_namespace_and_both_routes(self):
  # The tenant Admission policy compares HTTPRoute hostnames with this Namespace annotation.
  registry=json.loads((ROOT/'automation/platform-input-mappings.json').read_text())
  self.mapping=[entry for entry in registry if entry['root']=='app-auth' and entry['field']=='ui_hostname']
  self.save_mapping();self.request['root']='app-auth';self.request['values']={'ui_hostname':'dev.example.internal'}
  for destination in self.mapping[0]['targets']:
   relative=destination['file'].replace('{environment}','dev')
   target=self.repo/relative;target.parent.mkdir(parents=True,exist_ok=True)
   shutil.copy2(ROOT/relative,target)
  self.run_request()
  yaml=module.YAML()
  for destination in self.mapping[0]['targets']:
   target=self.repo/destination['file'].replace('{environment}','dev')
   document=yaml.load(target.read_text())
   if isinstance(document,list):self.assertEqual(document[0]['value'],['dev.example.internal'])
   else:self.assertEqual(document['metadata']['annotations']['platform.example/hostname'],'dev.example.internal')
 def check_selected_registry_targets(self,root,field,value,environment):
  registry=json.loads((ROOT/'automation/platform-input-mappings.json').read_text())
  self.mapping=[entry for entry in registry if entry['root']==root and entry['field']==field]
  self.save_mapping();self.request['root']=root;self.request['environment']=environment;self.request['values']={field:value}
  originals={}
  for destination in self.mapping[0]['targets']:
   relative=destination['file'].replace('{environment}',environment)
   target=self.repo/relative;target.parent.mkdir(parents=True,exist_ok=True)
   shutil.copy2(ROOT/relative,target);originals[target]=module.YAML().load(target.read_text())
  module.run(self.request,self.repo,environment,'111111111111',self.sha)
  for destination in self.mapping[0]['targets']:
   target=self.repo/destination['file'].replace('{environment}',environment)
   expected=copy.deepcopy(originals[target]);module.set_pointer(expected,destination['pointer'],value)
   self.assertEqual(expected,module.YAML().load(target.read_text()))
 def test_public_zone_updates_both_issuers_and_certificate_without_other_changes(self):
  for environment in ('dev','prod'):
   with self.subTest(environment=environment):
    self.check_selected_registry_targets('core','public_zone_name','training.company.internal',environment)
  self.assertEqual(3,len(self.mapping[0]['targets']))
 def test_cluster_updates_lbc_and_external_dns_owner_without_other_changes(self):
  for environment in ('dev','prod'):
   with self.subTest(environment=environment):
    self.check_selected_registry_targets('gateway','cluster_name','training-'+environment+'-eks',environment)
  self.assertEqual(2,len(self.mapping[0]['targets']))
 def test_identical_request_is_noop(self):self.run_request();self.assertEqual([],self.run_request())
 def test_wrong_account_changes_nothing(self):
  old=self.file.read_bytes();self.request['account_id']='222222222222'
  with self.assertRaises(ValueError):self.run_request()
  self.assertEqual(old,self.file.read_bytes())
 def test_unknown_value_is_rejected(self):
  self.request['values']['password']='fixture'
  with self.assertRaises(ValueError):self.run_request()
 def test_wrong_environment_is_rejected(self):
  self.request['environment']='prod'
  with self.assertRaises(ValueError):self.run_request()
 def test_newer_serial_blocks_older_apply(self):
  self.run_request();self.request['state_serial']=14;self.run_request();self.request['state_serial']=13
  with self.assertRaises(ValueError):self.run_request()
 def test_same_serial_conflicting_values_is_rejected(self):
  self.run_request();self.request['values']['metrics_bucket']='another-valid-bucket'
  with self.assertRaises(ValueError):self.run_request()
 def prepare_same_serial_expansion(self,new_revision=True):
  self.run_request()
  text=self.file.read_text();self.file.write_text(text+'  region: ap-northeast-2\n')
  self.mapping.append({'root':'observability','field':'region','type':'region','targets':[{'file':'gitops/platform/monitoring/overlays/{environment}/objstore.yml','pointer':'/config/region'}]})
  self.save_mapping();self.request['values']['region']='ap-northeast-2'
  if new_revision:
   subprocess.run(['git','-C',str(self.repo),'add','.'],check=True)
   subprocess.run(['git','-C',str(self.repo),'commit','-qm','reviewed field expansion'],check=True)
   self.sha=subprocess.check_output(['git','-C',str(self.repo),'rev-parse','HEAD'],text=True).strip()
   self.request['base_revision']=self.sha;self.request['apply_revision']=self.sha
 def test_same_serial_new_approved_fields_preserve_previous_values(self):
  self.prepare_same_serial_expansion();self.run_request()
  self.assertEqual([],self.run_request())
  receipt=json.loads((self.repo/'gitops/inputs/dev/observability.receipt.json').read_text())
  self.assertEqual(receipt['published_values'],self.request['values'])
 def test_expansion_cannot_change_previous_field(self):
  self.prepare_same_serial_expansion();self.request['values']['metrics_bucket']='changed-valid-bucket'
  old=self.file.read_bytes()
  with self.assertRaises(ValueError):self.run_request()
  self.assertEqual(old,self.file.read_bytes())
 def test_expansion_requires_new_approved_source(self):
  self.prepare_same_serial_expansion(new_revision=False)
  with self.assertRaises(ValueError):self.run_request()
 def test_apply_revision_must_match_trusted_publish_base(self):
  self.request['apply_revision']='b'*40
  with self.assertRaises(ValueError):self.run_request()
 def test_expansion_cannot_reuse_old_apply_revision(self):
  old_revision=self.sha;self.prepare_same_serial_expansion();self.request['apply_revision']=old_revision
  with self.assertRaises(ValueError):self.run_request()
 def test_expansion_cannot_name_unrelated_apply_revision(self):
  self.prepare_same_serial_expansion();self.request['apply_revision']='c'*40
  with self.assertRaises(ValueError):self.run_request()
 def test_legacy_same_serial_expansion_fails_closed(self):
  self.prepare_same_serial_expansion();p=self.repo/'gitops/inputs/dev/observability.receipt.json';receipt=json.loads(p.read_text());del receipt['published_values'];p.write_text(json.dumps(receipt))
  with self.assertRaises(ValueError):self.run_request()
 def test_tampered_previous_values_fail_closed(self):
  self.prepare_same_serial_expansion();p=self.repo/'gitops/inputs/dev/observability.receipt.json';receipt=json.loads(p.read_text());receipt['published_values']['metrics_bucket']='tampered-bucket';p.write_text(json.dumps(receipt))
  with self.assertRaises(ValueError):self.run_request()
 def test_same_serial_cannot_remove_existing_field(self):
  self.prepare_same_serial_expansion();self.run_request();self.mapping=self.mapping[:1];self.save_mapping();del self.request['values']['region']
  with self.assertRaises(ValueError):self.run_request()
 def test_expansion_cannot_change_lineage(self):
  self.prepare_same_serial_expansion();self.request['state_lineage']='aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee'
  with self.assertRaises(ValueError):self.run_request()
 def test_previous_receipt_target_boundary_cannot_be_reused(self):
  for field,value in [('environment','prod'),('account_id','222222222222'),('region','us-east-1'),('root','identity')]:
   with self.subTest(field=field):
    self.run_request();p=self.repo/'gitops/inputs/dev/observability.receipt.json';original=p.read_text();receipt=json.loads(original);receipt[field]=value;p.write_text(json.dumps(receipt))
    with self.assertRaises(ValueError):self.run_request()
    p.write_text(original)
 def test_symlink_target_is_rejected(self):
  self.file.unlink();self.file.symlink_to(self.repo/'schemas/platform-inputs.schema.json')
  with self.assertRaises(ValueError):self.run_request()
 def test_mapping_outside_selected_environment_is_rejected(self):
  self.mapping[0]['targets'][0]['file']='gitops/platform/monitoring/overlays/prod/objstore.yml';self.save_mapping()
  with self.assertRaises(ValueError):self.run_request()
 def test_invalid_schema_does_not_echo_values(self):
  self.request['unexpected']='private-fixture-value'
  with self.assertRaises(ValueError) as error:self.run_request()
  self.assertNotIn('private-fixture-value',str(error.exception))
 def test_selected_environment_named_values_file(self):
  target=self.repo/'gitops/platform/monitoring/values/dev-infrastructure.yaml';target.parent.mkdir();target.write_text('bucket: old-bucket\n')
  self.mapping[0]['targets']=[{'file':'gitops/platform/monitoring/values/{environment}-infrastructure.yaml','pointer':'/bucket'}];self.save_mapping()
  self.run_request();self.assertIn('team-dev-metrics',target.read_text())
 def test_selected_environment_epoch_overlay(self):
  target=self.repo/'gitops/platform/monitoring/overlays/dev-e2/objstore.yml';target.parent.mkdir();target.write_text('bucket: old-bucket\n')
  self.mapping[0]['targets']=[{'file':'gitops/platform/monitoring/overlays/{environment}-e2/objstore.yml','pointer':'/bucket'}];self.save_mapping()
  self.run_request();self.assertIn('team-dev-metrics',target.read_text())
 def test_existing_consumer_revision_changes_with_config(self):
  target=self.repo/'gitops/platform/monitoring/values/dev.yaml';target.parent.mkdir();target.write_text('prometheus:\n  prometheusSpec:\n    replicas: 1 # reviewed sizing\n')
  self.run_request();first=target.read_text()
  self.request['state_serial']=13;self.request['values']['metrics_bucket']='updated-valid-bucket';self.run_request()
  self.assertNotEqual(first,target.read_text());self.assertIn('reviewed sizing',target.read_text());self.assertIn('objstore-config-sha256',target.read_text())
 def configure_oidc(self,secret='$argocd-oidc-cognito:clientSecret'):
  target=self.repo/'gitops/platform/argocd/values/argo-cd-dev.yaml';target.parent.mkdir(parents=True)
  target.write_text('configs:\n  cm:\n    oidc.config: |\n      name: Cognito\n      issuer: https://old.internal\n      clientID: old-client\n      clientSecret: '+secret+'\n')
  self.mapping=[{'root':'delivery','field':'oidc_issuer','type':'endpoint','targets':[{'file':'gitops/platform/argocd/values/argo-cd-{environment}.yaml','pointer':'/configs/cm/oidc.config','embedded_pointer':'/issuer'}]}]
  self.save_mapping();self.request['root']='delivery';self.request['values']={'oidc_issuer':'https://cognito-idp.ap-northeast-2.amazonaws.com/ap-northeast-2_fixture'}
  return target
 def test_oidc_updates_issuer_and_keeps_external_credential_reference(self):
  target=self.configure_oidc();self.run_request();text=target.read_text()
  self.assertIn(self.request['values']['oidc_issuer'],text);self.assertIn('$argocd-oidc-cognito:clientSecret',text);self.assertIn('clientID: old-client',text)
 def test_oidc_inline_credential_blocks_all_writes(self):
  target=self.configure_oidc('fixture-sensitive-value');old=target.read_bytes()
  with self.assertRaises(ValueError):self.run_request()
  self.assertEqual(old,target.read_bytes());self.assertFalse((self.repo/'gitops/inputs/dev/delivery.receipt.json').exists())
 def test_oidc_client_secret_cannot_be_targeted(self):
  target=self.configure_oidc();self.mapping[0]['targets'][0]['embedded_pointer']='/clientSecret';self.save_mapping();old=target.read_bytes()
  with self.assertRaises(ValueError):self.run_request()
  self.assertEqual(old,target.read_bytes())
 def configure_documents(self,duplicate=False):
  target=self.repo/'gitops/apps/api/overlays/dev/externalsecret.patch.yaml';target.parent.mkdir(parents=True)
  target.write_text('kind: ExternalSecret\nmetadata:\n  name: commerce-api-runtime\nspec:\n  dataFrom:\n    - extract:\n        key: old-runtime\n---\nkind: ExternalSecret\nmetadata:\n  name: '+('commerce-api-runtime' if duplicate else 'commerce-api-migration')+'\nspec:\n  dataFrom:\n    - extract:\n        key: old-migration\n')
  self.mapping=[{'root':'data','field':'runtime_secret_arn','type':'arn','targets':[{'file':'gitops/apps/api/overlays/{environment}/externalsecret.patch.yaml','pointer':'/spec/dataFrom/0/extract/key','document_selector':{'kind':'ExternalSecret','name':'commerce-api-runtime'}}]}]
  self.save_mapping();self.request['root']='data';self.request['values']={'runtime_secret_arn':'arn:aws:secretsmanager:ap-northeast-2:111111111111:secret:dev/runtime-fixture'}
  return target
 def test_multi_document_updates_only_named_consumer(self):
  target=self.configure_documents();self.run_request();text=target.read_text()
  self.assertIn(self.request['values']['runtime_secret_arn'],text);self.assertIn('key: old-migration',text)
 def test_ambiguous_document_selector_blocks_all_writes(self):
  target=self.configure_documents(duplicate=True);old=target.read_bytes()
  with self.assertRaises(ValueError):self.run_request()
  self.assertEqual(old,target.read_bytes())
 def test_multi_document_requires_selector(self):
  self.configure_documents();del self.mapping[0]['targets'][0]['document_selector'];self.save_mapping()
  with self.assertRaises(ValueError):self.run_request()
 def test_shared_application_base_cannot_be_changed(self):
  self.mapping[0]['targets'][0]['file']='gitops/apps/api/base/runtime.yaml';self.save_mapping()
  with self.assertRaises(ValueError):self.run_request()
 def configure_database_request(self):
  target=self.repo/'gitops/platform/database-operations/requests/dev/job-database-bootstrap-reviewedrequest001.yaml';target.parent.mkdir(parents=True)
  target.write_text('apiVersion: batch/v1\nkind: Job\nmetadata:\n  name: database-bootstrap-reviewedrequest001\nspec:\n  activeDeadlineSeconds: 600\n  ttlSecondsAfterFinished: 3600\n  template:\n    spec:\n      containers:\n        - name: bootstrap\n          image: old-image\n')
  self.mapping=[{'root':'identity','field':'operator_image','type':'image','targets':[{'file':'gitops/platform/database-operations/requests/{environment}/job-database-bootstrap-reviewedrequest001.yaml','pointer':'/spec/template/spec/containers/0/image'}]}]
  self.save_mapping();self.request['root']='identity';self.request['values']={'operator_image':'111111111111.dkr.ecr.ap-northeast-2.amazonaws.com/database-operator@sha256:'+'a'*64}
  return target
 def test_bounded_native_database_request_accepts_only_immutable_image(self):
  target=self.configure_database_request();self.run_request();self.assertIn(self.request['values']['operator_image'],target.read_text())
 def test_database_image_tag_cannot_be_published(self):
  self.configure_database_request();self.request['values']['operator_image']='111111111111.dkr.ecr.ap-northeast-2.amazonaws.com/database-operator:reviewed'
  with self.assertRaises(ValueError):self.run_request()
 def test_database_image_in_another_account_cannot_be_published(self):
  self.configure_database_request();self.request['values']['operator_image']=self.request['values']['operator_image'].replace('111111111111','222222222222')
  with self.assertRaises(ValueError):self.run_request()
 def test_database_request_cannot_change_execution_time_or_command(self):
  self.configure_database_request();self.mapping[0]['targets'][0]['pointer']='/spec/activeDeadlineSeconds';self.save_mapping()
  with self.assertRaises(ValueError):self.run_request()
 def test_database_request_without_cleanup_deadline_is_rejected(self):
  target=self.configure_database_request();target.write_text(target.read_text().replace('  ttlSecondsAfterFinished: 3600\n',''))
  with self.assertRaises(ValueError):self.run_request()

if __name__=='__main__':unittest.main()
