#!/usr/bin/env python3
"""Provisional exact Grafana/Kafka cleanup ownership for one reviewed bundle.

No kind-wide exception: a live PVC/PV/CR must match the selected owner's current
checkpoint and its immutable action plan. At core apply only authenticated owner
completion and fresh exact volume absence replace the provisional permission.
"""
import importlib.util
import json
import os
from pathlib import Path
import re
import time

HERE=Path(__file__).resolve().parent

def load(name,file):
    spec=importlib.util.spec_from_file_location(name,HERE/file);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m

h=load('data_handoff_saved','saved-plan.py');c=load('data_handoff_control','lifecycle-state.py');b=load('data_handoff_barrier','lifecycle-barriers.py')
OWNERS=('hook:platform-observability','hook:self-managed-queue-topics-acl')
DATA_KINDS={'PersistentVolume','PersistentVolumeClaim','Kafka','KafkaTopic'}


def body_hash(obj):
    # Same canonicalization as the owner's lifecycle_hooks.object_digest.
    import hashlib
    return hashlib.sha256(json.dumps({k:v for k,v in obj.items() if k not in ('metadata','status')},sort_keys=True,separators=(',',':')).encode()).hexdigest()


def stable_snapshot(value):
    return {k:v for k,v in value.items() if k not in ('created_at','expires_at')}


def validate_owner(marker,context,owner):
    h.require(isinstance(marker,dict) and marker.get('schema')==1 and marker.get('step_id')==owner and marker.get('operation')=='down' and
              marker.get('generation')==context['generation'] and marker.get('snapshot_sha')==context['source_sha'] and
              re.fullmatch('[0-9a-f]{64}',marker.get('registration_sha256','')),'Missing exact selected data-owner checkpoint.')
    rc=marker.get('request_context',{});snapshot=marker.get('original',{})
    expected={'repository_id':context['repository_id'],'account':context['account'],'environment':context['environment'],
              'step_id':owner,'operation':'down','snapshot_sha':context['source_sha'],'generation':context['generation'],
              'registry_sha256':context['lifecycle_registry_sha256']}
    h.require(all(rc.get(k)==value for k,value in expected.items()) and snapshot.get('registry_sha256')==marker['registration_sha256'] and
              snapshot.get('checkpoint_generation')==context['generation'] and snapshot.get('account_id')==context['account'] and
              snapshot.get('environment')==context['environment'],'Data-owner snapshot scope/config differs.')
    return snapshot


def validate_plan(store,context,owner,marker,control,descriptor):
    b.descriptor(descriptor,b.PLAN_FIELDS)
    manifest=b.read(store,{'key':descriptor['manifest_key'],'version':descriptor['manifest_version'],'sha256':descriptor['manifest_sha']})
    rc=manifest.get('context',{})
    h.require(manifest.get('schema')==1 and manifest.get('kind')=='gitops-lifecycle' and rc==marker['request_context'] and manifest.get('control')==control,'Data-owner saved plan no longer owns exact checkpoint.')
    h.require(all(rc.get(k)==h.required(x) for k,x in (('run_id','GITHUB_RUN_ID'),('run_attempt','GITHUB_RUN_ATTEMPT'),('sha','GITHUB_SHA'))),'Data-owner plan is from another reviewed bundle run.')
    suffix=f"{context['repository_id']}/{rc['run_id']}/{rc['run_attempt']}/{rc['sha']}/{context['environment']}/hooks/{owner[5:]}/lifecycle-down/"
    prefix='ci-plans/'+suffix
    h.require(descriptor['manifest_key']==prefix+'manifest.json' and rc.get('prefix')==prefix and manifest.get('plan',{}).get('key')==prefix+'actions.json' and manifest['plan']['sha256']==descriptor['plan_sha'],'Data-owner plan namespace/action identity differs.')
    now=time.time();h.require(manifest['created_at']<=now<manifest['expires_at'] and manifest['expires_at']-manifest['created_at']==h.TTL_SECONDS,'Data-owner plan is expired.')
    action=b.read(store,manifest['plan'])
    h.require(action.get('step_id')==owner and action.get('operation')=='down' and stable_snapshot(action.get('snapshot',{}))==stable_snapshot(marker['original']) and
              action.get('completed')==marker.get('completed') and action.get('bootstrap_done')==marker.get('bootstrap_done'),'Data-owner planned targets differ from retained checkpoint.')


def volume_response(context,volume_id):
    value=h.aws('ec2','describe-volumes','--region',context['backend']['region'],'--filters','Name=volume-id,Values='+volume_id)
    h.require(isinstance(value.get('Volumes'),list) and not value.get('NextToken'),'Incomplete exact EBS observation.')
    return value['Volumes']


def match_live(snapshot,objects,context,owner):
    by_uid={i['object']['metadata']['uid']:i['object'] for i in objects};allowed=set()
    for row in snapshot.get('disposable_volumes',[]):
        contract=row['contract'];pv=by_uid.get(row['pv_uid']);pvc=by_uid.get(row['pvc_uid'])
        h.require(contract.get('approved_reset') is True and contract.get('source_sha')==context['source_sha'] and
                  contract.get('restore_mode')==('git-declared-empty-kafka' if owner.endswith('self-managed-queue-topics-acl') else 'git-provisioned-grafana'), 'Data-owner reset/source contract differs.')
        h.require(pv and pvc and pv.get('kind')=='PersistentVolume' and pvc.get('kind')=='PersistentVolumeClaim' and
                  pv['metadata']['name']==row['pv_name'] and pvc['metadata'].get('namespace')==contract['namespace'] and
                  pvc['metadata']['name']==contract['pvc'] and body_hash(pv)==row['pv_spec_sha256'] and body_hash(pvc)==row['pvc_spec_sha256'],'Provisional exact PVC/PV UID/spec differs.')
        spec=pv['spec'];h.require(spec.get('persistentVolumeReclaimPolicy')=='Delete' and spec.get('claimRef',{}).get('uid')==row['pvc_uid'] and
            spec['claimRef'].get('namespace')==contract['namespace'] and spec['claimRef'].get('name')==contract['pvc'] and
            spec.get('csi',{}).get('driver')=='ebs.csi.aws.com' and spec['csi'].get('volumeHandle')==contract['volume_id'],'Provisional CSI/PVC binding differs.')
        live=volume_response(context,contract['volume_id'])
        h.require(len(live)==1 and all(live[0].get(k)==v for k,v in row['volume_identity'].items()) and
                  {x['Key']:x['Value'] for x in live[0].get('Tags',[])}==row['tags'],'Provisional EBS incarnation/tags differ.')
        allowed.update((row['pv_uid'],row['pvc_uid']))
    if owner.endswith('self-managed-queue-topics-acl'):
        expected={r['uid']:r for app in snapshot.get('applications',[]) for r in app.get('resource_identities',[]) if r.get('kind') in ('Kafka','KafkaTopic')}
        approved=snapshot.get('queue',{}).get('uids',[])
        for uid,row in expected.items():
            obj=by_uid.get(uid)
            h.require(uid in approved and obj and obj.get('kind')==row['kind'] and obj['metadata'].get('namespace')=='messaging' and
                      obj['metadata']['name']==row['name'] and body_hash(obj)==row['spec_sha256'],'Provisional Kafka CR source/UID/spec differs.')
            allowed.add(uid)
    return allowed


def approved(config,objects,stage):
    h.require(stage in ('start','plan','verify','apply'),'Unknown data-owner handoff stage.')
    relevant=[i for i in objects if i['object']['kind'] in DATA_KINDS]
    if not relevant and stage!='apply':return []
    env=config.get('environment',config.get('_environment'));repo=h.required('GITHUB_REPOSITORY_ID')
    context={'repository_id':repo,'environment':env,'account':config['account_id'],'root':'terraform/environments/'+env+'/eks',
             'backend':{'bucket':config['state_bucket'],'region':config['region']},'operation':'down',
             'generation':h.required('LIFECYCLE_GENERATION'),'source_sha':h.required('LIFECYCLE_SNAPSHOT_SHA'),
             'lifecycle_registry_sha256':h.required('LIFECYCLE_CONFIG_SHA256')}
    store=h.Store(config['state_bucket'],config['account_id']);course,_=c.read_json(store,c.course_marker_key(repo,env))
    c.validate_course(course,repo,config['account_id'],config['state_bucket'],config['region'],env)
    h.require(course['phase']=='paused' and course['operation']=='down' and course['generation']==context['generation'] and course['snapshot_sha']==context['source_sha'] and course['registry_sha256']==context['lifecycle_registry_sha256'],'Data-owner handoff differs from active course.')
    order=list(reversed(course['steps']));current=h.required('LIFECYCLE_STEP_ID')
    h.require(current in order,'Current cleanup step is unselected.')
    descriptors=json.loads(os.environ.get('LIFECYCLE_BUNDLE_DESCRIPTORS','{}'));receipts=json.loads(os.environ.get('LIFECYCLE_BARRIER_RECEIPTS','{}'))
    allowed=set()
    for owner in OWNERS:
        if owner not in course['steps']:continue
        h.require(order.index(owner)<order.index(current),'Data owner must retire before basic core hooks.')
        marker,control=c.read_json(store,f'ci-lifecycle/{repo}/{env}/hook-{owner[5:]}.json')
        snapshot=validate_owner(marker,context,owner)
        h.require(snapshot.get('cluster_arn')==config['cluster_arn'],'Data owner belongs to another cluster.')
        if owner in course['completed']:
            b.for_consumer(store,context,receipts,step=owner)
            uids={row[k] for row in snapshot.get('disposable_volumes',[]) for k in ('pvc_uid','pv_uid')}|set(snapshot.get('queue',{}).get('uids',[]))
            h.require(not any(i['object']['metadata']['uid'] in uids for i in objects),'Completed data-owner objects remain.')
            for row in snapshot.get('disposable_volumes',[]):h.require(not volume_response(context,row['contract']['volume_id']),'Completed data-owner EBS volume remains.')
            continue
        h.require(stage!='apply','Data-owner completion is required before basic core mutation.')
        if stage!='start':validate_plan(store,context,owner,marker,control,descriptors.get(owner))
        allowed.update(match_live(snapshot,objects,context,owner))
    return sorted(allowed)
