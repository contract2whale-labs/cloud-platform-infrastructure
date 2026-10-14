"""Source-address constrained guard reusable by the saved-plan lifecycle engine.

Pure functions only. The engine authenticates checkpoint/approval/CAS and calls
these functions for exact saved plans; this file never executes Terraform/AWS.
"""
import json,re
from pathlib import Path
MANIFEST=json.loads(Path(__file__).with_name('manifest.json').read_text())
MODULES={'data','delivery','queue-managed'}
class Blocked(ValueError):pass

def require(test,message):
 if not test:raise Blocked(message)

def validate_decision(module,operation,decision):
 require(module in MODULES,'Unregistered runtime module')
 require(operation in ('down','up'),'Invalid operation')
 require(isinstance(decision,dict) and decision.get('environment') in ('dev','prod'),'Unregistered environment')
 if decision['environment']=='prod':require(decision.get('prod_lab_reset_approved') is True,'Production-account lab reset approval required')
 for gate in ('writers_quiesced','retained_verified','owner_cleanup_verified'):
  require(decision.get(gate) is True,'Missing verified barrier: '+gate)
 require(re.fullmatch('[0-9a-f]{64}',decision.get('completion_sha256','')) is not None,'Missing immutable completion digest')
 if module=='data':
  require(decision.get('mode')=='seed','Main database/cache restore inputs are not implemented; choose explicitly approved seed or stop')
  require(decision.get('seed_reset_approved') is True,'Disposable data reset not approved')
  for field in ('fixture_sha256','migration_sha256','seed_receipt_sha256'):
   require(re.fullmatch('[0-9a-f]{64}',decision.get(field,'')) is not None,'Missing verified fixture/migration/seed receipt: '+field)
  require(decision.get('media_consistency_verified') is True,'Retained media/reference consistency must be verified')
 if module=='queue-managed':
  require(decision.get('queue_mode')=='drained-disposable','No queue-message restore adapter')
  require(decision.get('drain_verified') is True and decision.get('epoch_inventory_verified') is True,'Queue drain and all epoch inventory required')

def allowed(module,address):
 base=re.sub(r'\[(?:"[^"\\]*"|[0-9]+)\]$','',address)
 return base in {'module.component.'+x for x in MANIFEST['roots'][module]['runtime_addresses']} or base in {'module.component.terraform_data.guard','module.component.terraform_data.contract','terraform_data.environment_boundary'}

def reject_protected(kind):
 require(not kind.startswith(('aws_s3_','aws_kms_','aws_ecr_','aws_secretsmanager_secret')),'Retained storage/key/credential resource in runtime plan')

def validate_plan(module,operation,plan,decision,original):
 """original: exact managed resource address -> identity captured before Down."""
 validate_decision(module,operation,decision)
 require(isinstance(original,dict) and original,'Original resource identity inventory is required')
 changed=set();seen=set()
 for row in plan.get('resource_changes',[]):
  if row.get('mode')=='data':continue
  address,kind=row.get('address'),row.get('type','')
  require(isinstance(address,str) and allowed(module,address),'Unknown resource address')
  require(address.removeprefix('module.component.').split('.')[0]==kind,'Address/type mismatch')
  reject_protected(kind)
  require(address in original,'Resource missing from completion inventory')
  require(address not in seen,'Duplicate resource change');seen.add(address)
  actions=row.get('change',{}).get('actions')
  require(actions in (["no-op"],["delete"] if operation=='down' else ["create"]),'Unexpected update/replacement/action')
  before=row.get('change',{}).get('before') or {}
  after=row.get('change',{}).get('after') or {}
  if actions==['delete']:
   require(before.get('id')==original[address].get('id') and before.get('id'),'Delete identity changed')
   changed.add(address)
   if kind=='aws_db_instance':
    require(before.get('deletion_protection') is False,'Database deletion protection is enabled')
    require(before.get('delete_automated_backups') is False,'Existing automated backups must be preserved')
   if kind=='aws_elasticache_serverless_cache':
    require(decision.get('cache_reset_approved') is True,'Cache reset not explicitly approved')
  if actions==['create']:
   changed.add(address)
   for key in ('name','identifier','cluster_name'):
    if original[address].get(key) is not None:
     require(after.get(key)==original[address][key],'Stable resource name changed or unknown')
 require(seen==set(original),'Plan must represent complete reviewed runtime inventory')
 if operation=='down':require(changed==set(original),'Down must delete exactly the reviewed runtime inventory')
 return {'module':module,'operation':operation,'changed':sorted(changed)}
