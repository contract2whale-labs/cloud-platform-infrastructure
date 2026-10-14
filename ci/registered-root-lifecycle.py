#!/usr/bin/env python3
"""Small policy adapter over the shared staged network executor (API 1)."""
import importlib.util,json,os,re,sys
from pathlib import Path
HERE=Path(__file__).resolve().parent
CI=HERE if (HERE/'saved-plan.py').is_file() else HERE.parent/'ci'
def load(name,path):
 spec=importlib.util.spec_from_file_location(name,path)
 m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
g=load('registered_ordinary_guard',HERE/'registered-root-guard.py')
e=load('shared_staged_lifecycle',CI/'network-lifecycle.py')
h=e.h
ROOT=None

def configure():
 global ROOT
 h.require(getattr(e,'ADAPTER_API',None)==1,'The reviewed shared executor extension is not installed; root stays blocked.')
 ROOT=h.required('ROOT_PATH');g.spec(ROOT)
 h.require(h.required('LIFECYCLE_ENGINE')==g.engine(ROOT),'Unregistered ordinary lifecycle engine.')
 h.require(re.fullmatch('[0-9a-f]{64}',h.required('LIFECYCLE_CONFIG_SHA256')),'Invalid reviewed registry digest.')
 selected=json.loads(h.required('LIFECYCLE_SELECTED_ROOTS'))
 h.require(isinstance(selected,list) and len(selected)==len(set(selected)) and ROOT in selected,'Invalid selected root inventory.')
 h.require(h.required('LIFECYCLE_ENVIRONMENT')==g.environment(ROOT),'Root and selected lifecycle environment differ.')
 for root in selected:g.key(root,g.environment(ROOT))
 e.ROOT,e.KEY=ROOT,g.key(ROOT);e.c.ROOT,e.c.KEY=e.ROOT,e.KEY
 h.require(re.fullmatch('[0-9a-f]{40}',h.required('LIFECYCLE_SNAPSHOT_SHA')) and re.fullmatch('[0-9]+-[0-9]+',h.required('LIFECYCLE_GENERATION')),'Invalid retained session identity.')
 # Registration is a code-reviewed implementation gate, not an env boolean.
 context={'root':ROOT,'lifecycle_registry_sha256':h.required('LIFECYCLE_CONFIG_SHA256')}
 g.assert_registration(Path(h.required('GITHUB_WORKSPACE')),context)
 inputs=e.current_inputs()
 if g.spec(ROOT)['disabled_edge']:h.require(inputs.get('enabled') is False,'Dev edge requires explicit enabled=false protected input.')
 if g.spec(ROOT).get('enabled_edge'):h.require(inputs.get('enabled') is True,'Prod edge requires explicit enabled=true protected input.')
 return selected

def marker_key(repository_id):
 h.require(str(repository_id).isdigit(),'Invalid repository ID.')
 return f"ci-lifecycle/{repository_id}/{g.environment(ROOT)}/{'-'.join(ROOT.split('/')[3:])}.json"

_original_payload=e.payload

def payload(workspace,directory,record,target):
 root,backend,context=_original_payload(workspace,directory,record,target)
 context['registered_source_sha256']=g.validate_source(directory/'payload',ROOT)
 context['registered_catalog_sha256']=h.digest((HERE/'registered-root-catalog.json').read_bytes())
 g.validate_context(context)
 return root,backend,context

_original_initial=e.initial_state

def initial_state(target):
 state,fingerprint=_original_initial(target)
 h.require(state is not None,'An exact existing own State is required; absence is not Down completion.')
 context={'root':ROOT,'environment':g.environment(ROOT),'workspace':'default','account':target['account'],
  'backend':{'key':g.key(ROOT),'bucket':target['bucket'],'region':target['region']},'operation':h.required('OPERATION')}
 g.validate_state(context,state)
 return state,fingerprint

def install():
 e.configure=configure;e.marker_key=marker_key;e.guard_module=lambda:g
 e.payload=payload;e.initial_state=initial_state
 e.KIND=g.KIND;e.COMPLETION_KIND=g.KIND+'-completion';e.LABEL='Registered root lifecycle'
 e.validate_initial_resources=lambda record,guard:None # Existing empty State is valid, never inferred absence.
 e.validate_supported_plan=lambda plan,guard:g.validate_supported_plan(plan,ROOT)
 e.validate_up=lambda plan,guard:g.validate_up(plan,{'root':ROOT,**_context_from_environment()})
 e.validate_down_completion=lambda context,state,record,guard:g.validate_down_completion(context,state)
 e.validate_restored_state=lambda context,plan,state,guard,upstream:g.validate_up_completion(plan,state,context)

def _context_from_environment():
 return {'environment':g.environment(ROOT),'workspace':'default','account':h.required('EXPECTED_ACCOUNT_ID'),
 'backend':{'key':g.key(ROOT),'bucket':h.required('STATE_BUCKET'),'region':h.required('AWS_REGION')},'operation':h.required('OPERATION')}

def validate_role(stage):
 # Exact central role families; Down AWS mutations use the destroy role only.
 if stage=='settings':return
 env=g.environment(h.required('ROOT_PATH'));account=h.required('EXPECTED_ACCOUNT_ID');operation=h.required('OPERATION')
 h.require(re.fullmatch('[0-9]{12}',account) and operation in ('up','down'),'Invalid account or lifecycle operation.')
 prefix=f'arn:aws:iam::{account}:role/gha-infra-{env}-'
 apply=prefix+('lifecycle-destroy' if operation=='down' else 'apply')
 expected=h.required('EXPECTED_APPLY_ROLE_ARN');active=h.required('AWS_ROLE_ARN')
 h.require(expected==apply,'Expected apply role does not match the account/environment/operation.')
 allowed=({apply} if stage=='apply' else {prefix+'apply',apply} if stage=='start' else {prefix+'plan',apply})
 h.require(active in allowed,'Active role cannot execute this registered-root lifecycle stage.')

def run(stage):
 validate_role(stage);install();e.run(stage)

if __name__=='__main__':
 os.umask(0o077)
 try:
  h.require(len(sys.argv)==2 and sys.argv[1] in ('settings','start','plan','verify','apply'),'Expected settings/start/plan/verify/apply.')
  run(sys.argv[1])
 except (h.SafeError,g.SafeError) as error:
  print('::error::'+str(error));sys.exit(1)
 except Exception:
  print('::error::Registered root lifecycle stopped. Keep pause and inspect private evidence; never replay the old plan.');sys.exit(1)
