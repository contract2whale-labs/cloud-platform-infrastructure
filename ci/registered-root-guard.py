#!/usr/bin/env python3
"""Bounded ordinary-root policy. It never deletes AWS objects directly.

Completion proves only the exact approved Terraform plan and this root's managed
State. Owner cleanup is a separately authenticated barrier, never an env flag.
"""
import importlib.util,json,os,re,tempfile,time
from pathlib import Path
HERE=Path(__file__).resolve().parent
CI=HERE if (HERE/'saved-plan.py').is_file() else HERE.parent/'ci'
def load(name,file):
 spec=importlib.util.spec_from_file_location(name,CI/file)
 m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
h=load('registered_saved_plan','saved-plan.py')
v=load('registered_state_reader','vpc-lifecycle-guard.py')
c=load('registered_course_control','lifecycle-state.py')
CATALOG=json.loads((HERE/'registered-root-catalog.json').read_text())
ROOTS=frozenset(CATALOG['roots'])
ENGINE='dev-registered-root-v1' # Backward-compatible Dev identifier; use engine(root).
KIND='registered-root-lifecycle'
SafeError=h.SafeError
require=h.require
managed_resources=v.managed_resources
normalize_resources=v.normalize_resources
VersionedStateReader=v.VersionedStateReader
PROTECTED_TYPES=('aws_s3_','aws_kms_','aws_secretsmanager_','aws_ecr_','aws_cognito_')
PROTECTED_IAM=re.compile(r'(?:^|[-_/])(?:ci|bootstrap|github|terraform-state|state-access|gha-infra)(?:$|[-_/])',re.I)
INDEX=r'(?:\[(?:0|[1-9][0-9]*|"(?:[^"\\\x00-\x1f]|\\["\\/bfnrt]|\\u[0-9a-fA-F]{4])*")\])?'
SOURCE_CACHE={}
VERIFIED_DOWN_PLANS={}
VERIFIED_DOWN_SESSION_TARGETS={}

def spec(root):
 require(root in ROOTS,'Unregistered ordinary lifecycle root; retained and unknown roots are forbidden.')
 return CATALOG['roots'][root]
def environment(root):
 require(isinstance(root,str) and re.fullmatch(r'terraform/environments/(dev|prod)/[a-z0-9][a-z0-9_-]*(?:/[a-z0-9][a-z0-9_-]*)*',root) and '..' not in root and '//' not in root and '/bootstrap/ci-identity' not in root,'Protected or invalid State dependency; it will not be read.')
 return root.split('/')[2]
def engine(root):return environment(root)+'-registered-root-v1'
def registry_path(workspace,root):return Path(workspace)/'ci'/('lifecycle-targets-prod.json' if environment(root)=='prod' else 'lifecycle-targets.json')
def key(root,expected_environment=None):
 env=environment(root)
 require(expected_environment is None or env==expected_environment,'Cross-environment State dependency is forbidden.')
 return '/'.join(root.split('/')[3:])+'/terraform.tfstate'
def allowed_types(root):return frozenset(spec(root)['allowed_addresses'].values())
def check_address(root,address,ty):
 exception=(root in {'terraform/environments/'+env+'/account-integrations' for env in ('dev','prod')} and ty=='aws_s3_bucket_notification' and address in ('module.component.aws_s3_bucket_notification.network_logs','module.component.aws_s3_bucket_notification.network_logs[0]'))
 require(isinstance(ty,str) and (not ty.startswith(PROTECTED_TYPES) or exception),'Retained resource type is forbidden in an ordinary lifecycle root.')
 matches=[a for a,t in spec(root)['allowed_addresses'].items() if t==ty and isinstance(address,str) and re.fullmatch(re.escape(a)+INDEX,address)]
 require(len(matches)==1,'Unreviewed managed address/type, nested module, or instance suffix.')
 return matches[0]
def validate_context(context):
 root=context.get('root');spec(root)
 require(context.get('environment')==environment(root) and context.get('workspace')=='default','Root and approved default-workspace environment differ.')
 require(isinstance(context.get('account'),str) and re.fullmatch('[0-9]{12}',context['account']),'Exact target account is required.')
 b=context.get('backend',{})
 require(b.get('key')==key(root) and b.get('region')=='ap-northeast-2' and isinstance(b.get('bucket'),str) and b['bucket'],'Unreviewed root backend or region.')
 if 'apply_role_arn' in context:
  mode='lifecycle-destroy' if context.get('operation')=='down' else 'apply'
  require(context['apply_role_arn']==f"arn:aws:iam::{context['account']}:role/gha-infra-{environment(root)}-{mode}",'Saved apply role is outside the exact account/environment/operation boundary.')
 return root

def validate_source(payload,root):
 """Exact raw/pinned-fmt reviewed file sets; no runtime source normalization."""
 s=spec(root);base=Path(payload).resolve()
 dirs=[root]+(['modules/'+s['module']] if s['module'] else [])
 observed={}
 for directory in dirs:
  path=base/directory
  require(path.is_dir() and not path.is_symlink() and path.resolve().is_relative_to(base),'Missing or redirected reviewed Terraform source.')
  for p in path.iterdir():
   require(not p.is_symlink(),'Source symlinks are forbidden.')
   if p.name.endswith('.tf.json'):raise SafeError('Unreviewed JSON Terraform source is forbidden.')
   if p.name.endswith('.tf'):
    observed[directory+'/'+p.name]=h.digest(p.read_bytes())
 def exact_variant(variant):
  raw=variant['files'];formatted=variant.get('formatted_files',raw)
  require(isinstance(raw,dict) and isinstance(formatted,dict) and set(raw)==set(formatted),'Invalid reviewed source catalog file membership.')
  if 'formatted_files' in variant:require(variant.get('formatter_version')=='1.16.0','Unreviewed source formatter version.')
  return set(observed)==set(raw) and all(observed[p] in (raw[p],formatted[p]) for p in raw)
 require(any(exact_variant(variant) for variant in s['source_variants']),'Unknown Terraform source/file set; review a new catalog before lifecycle use.')
 # All catalog entries are locally audited; no caller supplied source list or
 # digest can bless a new provisioner, external data source, or module.
 return h.digest(h.canonical(observed))

def reviewed_graph(workspace,context):
 registry=json.loads(registry_path(workspace,context['root']).read_text())
 require(h.digest(h.canonical(registry))==context['lifecycle_registry_sha256'],'Registry differs from the approved bundle.')
 graph=json.loads((Path(workspace)/'ci/deploy-roots.json').read_text()).get('dependencies')
 require(isinstance(graph,dict) and graph.get(context['root'])==spec(context['root'])['dependencies'],'Unreviewed State dependency graph.')
 for root,deps in graph.items():
  require(isinstance(root,str) and isinstance(deps,list) and len(deps)==len(set(deps)) and all(isinstance(d,str) for d in deps),'Malformed dependency graph.')
  env=environment(root)
  for dependency in deps:key(dependency,env)
 return graph

def assert_registration(workspace,context):
 require(spec(context['root']).get('course_member',True),'Source support cannot activate a root absent from the actual course graph.')
 reviewed_graph(workspace,context)
 registry=json.loads(registry_path(workspace,context['root']).read_text())
 require(registry['roots'].get(context['root'],{}).get('mode')=='adapter' and registry['roots'][context['root']].get('engine')==engine(context['root']),'Ordinary root registration is still blocked.')
 barriers=load('registered_barriers','lifecycle-barriers.py')
 for step in spec(context['root'])['required_down_hooks']:
  row=registry.get('hooks',{}).get(step[5:],{})
  family=('gitops' if step in barriers.BASIC_HOOKS else 'application' if step in barriers.APPLICATION_HOOKS else 'network-probes' if step in barriers.PROBE_HOOKS else None)
  require(step in barriers.HOOKS and family is not None and row.get('status')=='adapter' and row.get('engine')==environment(context['root'])+'-'+family+'-v1','Required hook has no reviewed executable receipt authenticator; root stays blocked.')

def read_upstreams(workspace,context,*,load_state=None):
 validate_context(context);graph=reviewed_graph(workspace,context)
 names=graph[context['root']]
 # Validate every key before making even one State read.
 keys={root:key(root,environment(context['root'])) for root in names}
 reader=load_state or VersionedStateReader(context['backend']['bucket'],context['account'],context['backend']['region'])
 return {root:reader(k) for root,k in sorted(keys.items())}
def upstream_fingerprints(workspace,context,*,load_state=None):
 return {root:row['fingerprint'] for root,row in read_upstreams(workspace,context,load_state=load_state).items()}

def check_values(context,row,*,planned=False):
 root=context['root'];ty=row['type'];values=row['values']
 check_address(root,row['address'],ty)
 require(isinstance(values,dict),'Resource values are missing.')
 if not planned:require(isinstance(values.get('id'),str) and values['id'],'Managed resource has no stable identity.')
 if ty=='aws_s3_bucket_notification':require(row['address']=='module.component.aws_s3_bucket_notification.network_logs[0]','Only the exact count-zero-or-one network log notification is supported.')
 if ty.startswith('aws_iam_'):
  for field in (('role','role_name') if ty=='aws_iam_role_policy' else ('name','id','role','role_name','policy_arn','arn')):
   value=values.get(field)
   if isinstance(value,str):
    require(not PROTECTED_IAM.search(value),'CI/bootstrap/State-access IAM identities are protected.')
    for env in ('AWS_ROLE_ARN','EXPECTED_APPLY_ROLE_ARN'):
     role=os.environ.get(env)
     if role:require(value not in (role,role.rsplit('/',1)[-1]),'The active CI role cannot be changed by an ordinary root.')
 for field in ('arn','role_arn','cluster_arn'):
  arn=values.get(field)
  if isinstance(arn,str) and arn.startswith('arn:'):
   parts=arn.split(':',5)
   require(len(parts)==6 and parts[1]=='aws' and parts[4] in ('',context['account'],'aws'),'Resource identity crosses the approved account.')
 if spec(root)['disabled_edge']:require(ty=='terraform_data','Dev edge must own no AWS resources.')

def validate_state(context,state,expected_resources=None,upstream_states=None):
 validate_context(context)
 rows=managed_resources(state)
 for row in rows:check_values(context,row)
 if expected_resources is not None and context.get('operation')!='up':
  original={r['address']:r for r in expected_resources}
  require(len(original)==len(expected_resources),'Duplicate original managed identity.')
  for row in rows:
   require(original.get(row['address'])=={'address':row['address'],'type':row['type'],'id':row['values']['id']},'Managed identity changed or expanded after the original snapshot.')
 return rows

def planned_rows(plan):
 return managed_resources({'format_version':'1.0','values':plan.get('planned_values',{})})
def validate_supported_plan(plan,root,context=None):
 require(isinstance(plan,dict) and str(plan.get('format_version','')).split('.')[0]=='1' and plan.get('errored',False) is False and plan.get('complete',True) is True and not plan.get('deferred_changes') and not plan.get('resource_drift'),'Incomplete, deferred, or unsupported Terraform plan.')
 for row in planned_rows(plan):
  check_address(root,row['address'],row['type'])
  if context:check_values(context,row,planned=True)
 for row in plan.get('resource_changes',[]):
  require(isinstance(row,dict) and row.get('mode') in ('data','managed'),'Unknown planned resource mode.')
  require(not row.get('deposed') and not row.get('previous_address'),'Moved or deposed resources require separate recovery.')
  if row['mode']=='data':
   require(row.get('type')!='external','External data programs are not supported.');continue
  check_address(root,row.get('address'),row.get('type'))
  change=row.get('change',{})
  require(change.get('actions') in (['create'],['update'],['no-op'],['delete']),'Replacement, forget, or unknown action is forbidden.')
  require(not change.get('importing'),'Imports are outside the lifecycle contract.')
  if context:
   for field in ('before','after'):
    if change.get(field) is not None:check_values(context,dict(address=row['address'],type=row['type'],values=change[field]),planned=True)
 # Configuration must describe exactly the source-derived declarations, even
 # when count=0 hides unknown managed instances in evaluated planned_values.
 def config(module,prefix=''):
  require(isinstance(module,dict),'Evaluated source configuration is missing.')
  for row in module.get('resources',[]):
   require(isinstance(row,dict) and row.get('mode') in ('data','managed'),'Unknown configuration resource mode.')
   require(not row.get('provisioners'),'Provisioners are forbidden.')
   address=prefix+row.get('address','')
   if row['mode']=='managed':
    # Disabled Dev edge source legitimately declares AWS resources, all gated
    # by enabled=false. Exact source hashes authorize declarations, not objects.
    if not spec(root)['disabled_edge']:check_address(root,address,row.get('type'))
   else:require(row.get('type')!='external','External data source is forbidden.')
  calls=module.get('module_calls',{})
  allowed={'component'} if prefix=='' and spec(root)['module'] else set()
  require(set(calls)<=allowed,'Unreviewed module call in evaluated source.')
  for name,call in calls.items():
   require(call.get('source')==('../../../../../modules/' if '/platform/' in root else '../../../../modules/')+spec(root)['module'],'Module source differs from the reviewed local source.')
   config(call.get('module'),prefix+'module.'+name+'.')
 config(plan.get('configuration',{}).get('root_module'))

def validate_plan_contracts(context,plan,upstream):
 validate_supported_plan(plan,context['root'],context)
 require(set(upstream)==set(spec(context['root'])['dependencies']),'Missing upstream State binding.')
 if spec(context['root'])['disabled_edge']:
  require(plan.get('variables',{}).get('enabled',{}).get('value') is False,'Dev edge lifecycle requires explicit effective enabled=false.')
 if spec(context['root']).get('enabled_edge'):
  require(plan.get('variables',{}).get('enabled',{}).get('value') is True,'Prod edge lifecycle requires explicit effective enabled=true.')
 if spec(context['root']).get('notification_guard'):notification_guard().verify(context,plan,h.aws)
 for row in upstream.values():
  require(isinstance(row,dict) and isinstance(row.get('fingerprint'),dict),'Unpinned upstream State.')
  if context['operation']=='up':require(row.get('state') is not None and bool(managed_resources(row['state'])),'Up requires restored managed prerequisite State.')

def validate_up(plan,context):
 validate_supported_plan(plan,context['root'],context)
 for row in plan.get('resource_changes',[]):
  if row.get('mode')=='managed':require(row['change']['actions'] in (['create'],['update'],['no-op']),'Up allows create/update/no-op only.')

def validate_up_completion(plan,state,context):
 validate_up(plan,context);actual=validate_state(context,state)
 expected={r['address']:r['type'] for r in planned_rows(plan)}
 require({r['address']:r['type'] for r in actual}==expected,'Up State is not the exact managed address/type inventory of the approved plan.')
 # Known before/after IDs cannot silently become another identity.
 for planned in planned_rows(plan):
  identity=planned['values'].get('id')
  if isinstance(identity,str) and identity:
   require(next(r for r in actual if r['address']==planned['address'])['values']['id']==identity,'Up completed with a different known resource identity.')
 result={'scope':'exact-approved-managed-state','managed_count':len(actual),'cloud_absence_proven':False}
 subscriptions=verify_email_subscriptions(context,actual)
 if subscriptions:result['confirmed_email_subscriptions']=subscriptions;result['notification_delivery_unverified']=True
 if spec(context['root']).get('notification_guard'):result['notification_ownership']=notification_guard().completion(context,plan,actual,h.aws)
 if spec(context['root']).get('enabled_edge'):result['prod_edge_publication']=load('registered_edge_publication','edge-publication-proof.py').verify(context,actual,h.aws)
 return result

def notification_guard():return load('registered_notification_ownership','notification-lifecycle-guard.py')

def verify_email_subscriptions(context,rows):
 # GetSubscriptionAttributes proves confirmation of the exact ARN. It does not
 # prove message delivery. ConfirmationWasAuthenticated=false may be a valid
 # email-link confirmation and is not equivalent to PendingConfirmation=true.
 # https://docs.aws.amazon.com/sns/latest/api/API_GetSubscriptionAttributes.html
 result=[]
 for row in rows:
  values=row['values']
  if row['type']!='aws_sns_topic_subscription' or values.get('protocol') not in ('email','email-json'):continue
  arn=values.get('arn') or values.get('id');topic=values.get('topic_arn')
  prefix=f"arn:aws:sns:{context['backend']['region']}:{context['account']}:"
  require(isinstance(topic,str) and topic.startswith(prefix) and isinstance(arn,str) and arn.startswith(topic+':') and re.fullmatch(r'[0-9a-fA-F-]{36}',arn[len(topic)+1:]) and values.get('pending_confirmation') is False,'Email subscription requires confirmation; keep the lifecycle paused and create a fresh Up plan after reconfirmation.')
  attributes=h.aws('sns','get-subscription-attributes','--subscription-arn',arn,'--region',context['backend']['region']).get('Attributes')
  require(isinstance(attributes,dict) and attributes.get('SubscriptionArn')==arn and attributes.get('TopicArn')==topic and attributes.get('Owner')==context['account'] and attributes.get('PendingConfirmation')=='false','Live SNS subscription confirmation/account/topic was not established; completion is blocked.')
  result.append({'address':row['address'],'subscription_arn':arn,'confirmed':True})
 return result

def consumer_states(workspace,context,*,load_state=None):
 graph=reviewed_graph(workspace,context);reached={context['root']}
 while True:
  extra={r for r,deps in graph.items() if set(deps)&reached}
  if extra<=reached:break
  reached|=extra
 keys={r:key(r,environment(context['root'])) for r in reached-{context['root']}}
 reader=load_state or VersionedStateReader(context['backend']['bucket'],context['account'],context['backend']['region'])
 result={r:reader(k) for r,k in sorted(keys.items())}
 return {r:item for r,item in result.items() if item['state'] is not None and managed_resources(item['state'])}

def course_context(store,context):
 target=dict(repository_id=context['repository_id'],account=context['account'],bucket=context['backend']['bucket'],region=context['backend']['region'],environment=environment(context['root']))
 course,_=c.read_json(store,c.course_marker_key(target['repository_id'],target['environment']))
 require(course is not None,'Course checkpoint is missing.')
 c.validate_course(course,**target)
 require(course['phase']=='paused' and course['operation']==context['operation'] and course['generation']==context['generation'] and course['snapshot_sha']==context['source_sha'] and course['registry_sha256']==context['lifecycle_registry_sha256'],'Hook barrier belongs to another course session.')
 require(course['completed']==(list(reversed(course['steps'])) if context['operation']=='down' else course['steps'])[:len(course['completed'])],'Completed dependency steps are not an ordered prefix.')
 return course

def hook_barriers(context,stage,*,store=None):
 row=spec(context['root']);hooks=list(row['required_down_hooks']);conditional=row.get('conditional_down_hooks',[])
 if not hooks and not conditional:return {}
 store=store or h.Store(context['backend']['bucket'],context['account'])
 course=course_context(store,context)
 hooks += [step for step in conditional if step in course['steps']]
 if not hooks:return {}
 require(context['root'] in course['steps'],'Root is absent from the approved course sequence.')
 order=list(reversed(course['steps']))
 before=order[:order.index(context['root'])]
 require(set(hooks)<=set(before),'Owner cleanup is not before this Terraform root.')
 helper=load('registered_barrier_proofs','lifecycle-barriers.py')
 receipts=json.loads(os.environ.get('LIFECYCLE_BARRIER_RECEIPTS','{}'))
 require(isinstance(receipts,dict),'Invalid barrier receipt descriptors.')
 descriptors=json.loads(os.environ.get('LIFECYCLE_BUNDLE_DESCRIPTORS','{}'))
 require(isinstance(descriptors,dict),'Invalid bundle descriptors.')
 result={}
 for step in hooks:
  if step in course['completed']:
   saved=course.get('barriers',{}).get(step,{}).get('plan')
   helper.descriptor(saved,helper.PLAN_FIELDS)
   require(step not in descriptors or descriptors[step]==saved,'Completed hook does not match this bundle action plan.')
   helper.for_consumer(store,context,receipts,step=step)
   result[step]=saved
   continue
  require(stage=='plan','Required owner cleanup hook is not complete.')
  # A not-yet-completed hook needs a current reviewed action plan in this bundle.
  d=descriptors.get(step);helper.descriptor(d,helper.PLAN_FIELDS)
  manifest=helper.read(store,{'key':d['manifest_key'],'version':d['manifest_version'],'sha256':d['manifest_sha']})
  wanted={k:context[k] for k in ('repository_id','account','run_id','run_attempt','sha','generation','environment','operation')}
  wanted.update(step_id=step,snapshot_sha=context['source_sha'],registry_sha256=context['lifecycle_registry_sha256'],completed_chapter=course['completed_chapter'])
  actual=manifest.get('context',{})
  prefix=f"ci-plans/{context['repository_id']}/{context['run_id']}/{context['run_attempt']}/{context['sha']}/{context['environment']}/hooks/{step[5:]}/lifecycle-down/"
  require(manifest.get('kind')=='gitops-lifecycle' and manifest.get('schema')==1 and all(actual.get(k)==value for k,value in wanted.items()) and actual.get('prefix')==prefix and d['manifest_key']==prefix+'manifest.json','Hook action manifest is outside the reviewed source/session/root.')
  plan=manifest.get('plan',{})
  require(plan.get('key')==prefix+'actions.json' and plan.get('sha256')==d['plan_sha'],'Hook saved action descriptor mismatch.')
  payload=helper.read(store,plan)
  require(payload.get('step_id')==step and payload.get('operation')=='down','Hook saved actions target another operation.')
  require(type(manifest.get('created_at')) in (int,float) and type(manifest.get('expires_at')) in (int,float) and manifest['created_at']<=time.time()<manifest['expires_at'] and manifest['expires_at']-manifest['created_at']==h.TTL_SECONDS,'Hook action plan expired.')
  result[step]=d
 return result

def guard_destroy(workspace,context,state,plan,expected_resources=None,upstream_states=None,stage='apply',*,load_state=None,store=None):
 require(stage in ('plan','apply'),'Unknown guard stage.')
 assert_registration(workspace,context)
 validate_state(context,state,expected_resources,upstream_states)
 validate_plan_contracts(context,plan,upstream_states or {})
 proof=load('registered_consumer_proof','network-consumer-proof.py')
 identities=proof.validate_registered_delete_plan(state,plan,context)
 session_evidence={}
 if spec(context['root']).get('dev_session_proof'):
  helper=load('registered_dev_sessions','dev-app-session-proof.py')
  relay=(upstream_states or {}).get('terraform/environments/dev/platform/private-api',{}).get('state')
  require(isinstance(relay,dict),'Exact private API State is required for Dev session closure.')
  target=helper.capture(context,managed_resources(state),managed_resources(relay),expected_resources)
  session_evidence=helper.verify(target,h.aws)
  if stage=='apply':VERIFIED_DOWN_SESSION_TARGETS[h.digest(h.canonical(context))]=target
 hooks=hook_barriers(context,stage,store=store)
 consumers=consumer_states(workspace,context,load_state=load_state)
 deferred={}
 if consumers:
  require(stage=='plan','Dependent Terraform State remains managed; root deletion is blocked.')
  deferred=proof.prove_consumers(workspace,context,consumers,proof.selected_descriptors(),store=store)
 if stage=='apply' and spec(context['root']).get('notification_guard'):VERIFIED_DOWN_PLANS[h.digest(h.canonical(context))]=plan
 return {'scope':'own-empty-managed-state-only','cloud_absence_proven':False,**identities,
  'deferred_runtime_consumer_check':bool(deferred),'deferred_consumers':deferred,
  'deferred_hook_barriers':hooks if stage=='plan' else {},'authenticated_completed_hooks':sorted(hooks) if stage=='apply' else [],
  'hook_plan_descriptors':hooks,'dev_app_sessions_closed':session_evidence}

def validate_down_completion(context,state):
 validate_state(context,state)
 require(not managed_resources(state),'Managed resources remain in this root State; completion is blocked.')
 result={'scope':'own-empty-managed-state-only','managed_count':0,'cloud_absence_proven':False}
 if spec(context['root']).get('dev_session_proof'):
  target=VERIFIED_DOWN_SESSION_TARGETS.pop(h.digest(h.canonical(context)),None)
  require(target is not None,'Exact pre-apply Dev session target is missing; completion is blocked.')
  result['dev_app_sessions_closed']=load('registered_completed_dev_sessions','dev-app-session-proof.py').verify(target,h.aws)
 if spec(context['root']).get('notification_guard'):
  plan=VERIFIED_DOWN_PLANS.pop(h.digest(h.canonical(context)),None)
  require(plan is not None,'Exact pre-apply notification plan is unavailable; completion is blocked.')
  result['notification_ownership']=notification_guard().completion(context,plan,[],h.aws)
 return result
