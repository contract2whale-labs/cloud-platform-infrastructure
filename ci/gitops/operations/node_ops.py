"""Bounded T8A node protection cycle and original-UID recovery."""
import copy,json,time
IDS=('node-protection-cycle','node-protection-restore')
KEY='cluster-autoscaler.kubernetes.io/scale-down-disabled'
PATH='/metadata/annotations/cluster-autoscaler.kubernetes.io~1scale-down-disabled'
def snapshot(io,operation,r,c,marker):
 if operation.endswith('restore'):
  io.require(marker and marker.get('operation') in IDS,'Original protection marker required');target=copy.deepcopy(marker['target'])
 else:
  io.require(type(r.get('hold_seconds')) is int and 1<=r['hold_seconds']<=900,'Protection observation duration must be 1–900 seconds')
  io.require(len(r['nodes'])==2 and len({x['name'] for x in r['nodes']})==2,'Exactly two approved original Nodes required')
  target={'nodes':[],'hold_seconds':r['hold_seconds']}
  for requested in r['nodes']:
   obj=io.kube('nodes','',requested['name']);md=obj['metadata'];labels=md.get('labels',{})
   io.require(md['uid']==requested['uid'] and labels.get('workload')=='app' and labels.get('eks.amazonaws.com/nodegroup')=='contract2whale-dev-eks-app','Node UID/workload/nodegroup ownership differs')
   before=md.get('annotations',{}).get(KEY);io.require(before in (None,'true','false'),'Unexpected original protection value')
   target['nodes'].append({'name':md['name'],'uid':md['uid'],'before':before,'provider_id':obj['spec']['providerID']})
 for row in target['nodes']:current(io,row)
 return target

def current(io,row):
 obj=io.kube('nodes','',row['name']);md=obj['metadata']
 io.require(md['uid']==row['uid'] and obj['spec']['providerID']==row['provider_id'] and md.get('labels',{}).get('workload')=='app' and md.get('labels',{}).get('eks.amazonaws.com/nodegroup')=='contract2whale-dev-eks-app','Original Node identity changed')
 io.require(md.get('annotations',{}).get(KEY) in (row['before'],'true'),'Another writer changed protection; preserve it')
 return obj

def patch(io,row,value):
 obj=current(io,row);md=obj['metadata'];annotations=md.get('annotations',{});old=annotations.get(KEY)
 if old==value:return
 actions=[{'op':'test','path':'/metadata/uid','value':row['uid']},{'op':'test','path':'/metadata/resourceVersion','value':md['resourceVersion']}]
 if 'annotations' not in md:actions.append({'op':'add','path':'/metadata/annotations','value':{}})
 if KEY in annotations:actions.append({'op':'test','path':PATH,'value':old})
 actions.append({'op':'remove','path':PATH} if value is None else {'op':'add','path':PATH,'value':value})
 io.ops.run(['kubectl','patch','node',row['name'],'--type=json','-p',json.dumps(actions)])
 io.require(io.kube('nodes','',row['name'])['metadata'].get('annotations',{}).get(KEY)==value,'Node protection change not verified')

def apply(io,operation,target,r,mark):
 mark('active',target)
 try:
  if operation.endswith('cycle'):
   for row in target['nodes']:patch(io,row,'true')
   time.sleep(target['hold_seconds'])
 finally:
  try:
   for row in target['nodes']:patch(io,row,row['before'])
   mark('idle',target)
  except Exception:mark('recovery-required',target);raise
 return {'restored_node_uids':[x['uid'] for x in target['nodes']]}
