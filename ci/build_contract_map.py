"""Offline convenience builder from actual reviewed metadata/source artifacts.

No defaults authorize reset. Does not contact AWS/GitHub or guess IDs/digests.
"""
import argparse,hashlib,json
from pathlib import Path

def digest(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def build(metadata,decisions,seed_source,migration_manifest,seed_assertions,drain_script,environment="dev"):
 if environment not in ('dev','prod'):raise ValueError('Unsupported environment')
 required={'application_namespace','application_repository','application_repository_id','application_source_sha','application_image_digest'}
 if set(metadata)!=required:raise ValueError('Supply the exact metadata fields from actual completion/build outputs')
 for key in ('disposable_runtime_approved','seed_reset_approved','cache_reset_approved','media_consistency_verified','epoch_inventory_verified'):
  if decisions.get(key) is not True:raise ValueError('Explicit reviewed decision required: '+key)
 common={'schema':1,'environment':environment,'application_namespace':metadata['application_namespace'],'disposable_runtime_approved':True}
 delivery={**common,'root':'terraform/environments/'+environment+'/delivery'}
 data={**common,'root':'terraform/environments/'+environment+'/data','mode':'seed','seed_reset_approved':True,'cache_reset_approved':True,'media_consistency_verified':True,
       **{k:metadata[k] for k in ('application_repository','application_repository_id','application_source_sha','application_image_digest')},
       'fixture_source_path':'src/migration-scripts/initial-data-seed.ts','fixture_sha256':digest(seed_source),'migration_sha256':digest(migration_manifest),'seed_receipt_sha256':digest(seed_assertions)}
 queue={**common,'root':'terraform/environments/'+environment+'/platform/queue','queue_mode':'drained-disposable','epoch_inventory_verified':True,'drain_script_sha256':digest(drain_script)}
 if environment=='prod':
  if decisions.get('prod_lab_reset_approved') is not True:raise ValueError('Explicit Prod lab reset decision required')
  for contract in (data,delivery,queue):contract['prod_lab_reset_approved']=True
  for key in ('prod_protection_receipt','prod_protection_request_sha256'):
   if not decisions.get(key):raise ValueError('Actual protected production transition evidence required: '+key)
   data[key]=decisions[key]
 return {'data':data,'delivery':delivery,'platform/queue':queue}
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__)
 p.add_argument('--environment',choices=('dev','prod'),default='dev')
 for key in ('metadata','decisions','seed-source','migration-manifest','seed-assertions','drain-script','output'):p.add_argument('--'+key,required=True)
 a=p.parse_args();result=build(json.loads(Path(a.metadata).read_text()),json.loads(Path(a.decisions).read_text()),a.seed_source,a.migration_manifest,a.seed_assertions,a.drain_script,a.environment)
 out=Path(a.output);out.write_text(json.dumps(result,indent=2)+'\n');out.chmod(0o600)
