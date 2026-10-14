"""Offline BU03 retention, logging and deferred-consumer guard tests."""
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch
from types import SimpleNamespace

HERE=Path(__file__).resolve().parent

def load(name,file):
    spec=importlib.util.spec_from_file_location(name,HERE/file)
    m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m

g=load('new_network_guard','network-lifecycle-guard.py')
t=load('old_guard_fixtures','test_vpc_lifecycle_guard.py')


def storage(context):
    name=f"cp-dev-network-logs-{context['account']}-{context['backend']['region']}";arn='arn:aws:s3:::'+name
    rows=[t.resource(kind,'network_logs',name,bucket=name,**({'arn':arn,'force_destroy':False} if kind=='aws_s3_bucket' else {})) for kind in sorted(g.STORAGE_TYPES)]
    attrs={row['type']:row['instances'][0]['attributes'] for row in rows}
    attrs['aws_s3_bucket_ownership_controls']['rule']=[{'object_ownership':'BucketOwnerEnforced'}]
    attrs['aws_s3_bucket_server_side_encryption_configuration']['rule']=[{'apply_server_side_encryption_by_default':[{'sse_algorithm':'AES256','kms_master_key_id':''}]}]
    attrs['aws_s3_bucket_public_access_block'].update(dict.fromkeys(('block_public_acls','block_public_policy','ignore_public_acls','restrict_public_buckets'),True))
    attrs['aws_s3_bucket_versioning']['versioning_configuration']=[{'status':'Enabled','mfa_delete':''}]
    attrs['aws_s3_bucket_lifecycle_configuration']['rule']=[{'status':'Disabled','expiration':[{'days':90}]}]
    attrs['aws_s3_bucket_policy']['policy']=json.dumps({'Statement':[{'Effect':'Deny','Principal':'*','Action':['s3:DeleteBucket','s3:DeleteObject','s3:DeleteObjectVersion'],'Resource':[arn,arn+'/*']}]})
    return t.state_of(rows)|{'outputs':{'network_logs_bucket_name':{'value':name},'network_logs_bucket_arn':{'value':arn}}}


class CumulativeGuardTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.workspace=Path(self.tmp.name)
        (self.workspace/'ci').mkdir();self.graph={g.VPC:[],g.PEER:[],g.TRANSIT:[g.VPC,g.PEER], 'terraform/environments/dev/eks':[g.VPC]};self.write_graph()
        self.f=t.Fixture();self.f.context.update(repository_id='17',run_id='1',run_attempt='1',sha='a'*40,source_sha='a'*40,generation='1-1',selected_roots=[g.VPC])
        self.f.responses.update({('ec2','describe-flow-logs'):{'FlowLogs':[]},('route53resolver','list-resolver-query-log-config-associations'):{'ResolverQueryLogConfigAssociations':[]},('route53resolver','list-resolver-query-log-configs'):{'ResolverQueryLogConfigs':[]},('ec2','get-subnet-cidr-reservations'):{'SubnetIpv4CidrReservations':[],'SubnetIpv6CidrReservations':[]}})
        self.upstream={g.LOG:{'state':None,'fingerprint':{'exists':False}}};self.deps={};self.loads=[]
    def write_graph(self): (self.workspace/'ci/deploy-roots.json').write_text(json.dumps({'dependencies':self.graph}))
    def reader(self,key):
        self.loads.append(key);return self.deps.get(key,{'state':None,'fingerprint':{'exists':False}})
    def run_guard(self,stage='plan',**kwargs):
        return g.guard_destroy(self.workspace,self.f.context,self.f.state,t.plan_of(self.f.state),expected_resources=g.normalize_resources(self.f.state),upstream_states=self.upstream,stage=stage,aws_call=self.f.aws,load_state=self.reader,**kwargs)
    def add_logging(self):
        self.upstream[g.LOG]={'state':storage(self.f.context),'fingerprint':{'exists':True,'version':'logs1'}}
        name,arn=g.storage_contract(self.f.context,self.upstream)
        self.f.state['resources'] += [
            t.resource('aws_flow_log','vpc','fl-0123456789abcdef0',vpc_id=t.VPC,log_destination_type='s3',log_destination=arn+'/flow/'),
            t.resource('aws_route53_resolver_query_log_config','vpc','rqlc-123456',destination_arn=arn+'/dns/'),
            t.resource('aws_route53_resolver_query_log_config_association','vpc','rqlca-123456',resource_id=t.VPC,resolver_query_log_config_id='rqlc-123456'),
            t.resource('aws_ec2_subnet_cidr_reservation','pod','scr-123456',subnet_id=t.SUBNET,cidr_block='10.1.0.16/28',reservation_type='prefix'),
        ]
        self.f.responses[('ec2','describe-flow-logs')]={'FlowLogs':[{'FlowLogId':'fl-0123456789abcdef0','ResourceId':t.VPC,'LogDestinationType':'s3','LogDestination':arn+'/flow/','FlowLogStatus':'ACTIVE'}]}
        self.f.responses[('route53resolver','list-resolver-query-log-config-associations')]={'ResolverQueryLogConfigAssociations':[{'Id':'rqlca-123456','ResourceId':t.VPC,'ResolverQueryLogConfigId':'rqlc-123456','Status':'CREATED'}]}
        self.f.responses[('route53resolver','list-resolver-query-log-configs')]={'ResolverQueryLogConfigs':[{'Id':'rqlc-123456','OwnerId':t.ACCOUNT,'DestinationArn':arn+'/dns/','Status':'CREATED','ShareStatus':'NOT_SHARED'}]}
        self.f.responses[('ec2','get-subnet-cidr-reservations')]={'SubnetIpv4CidrReservations':[{'SubnetCidrReservationId':'scr-123456','SubnetId':t.SUBNET,'OwnerId':t.ACCOUNT,'Cidr':'10.1.0.16/28','ReservationType':'prefix'}],'SubnetIpv6CidrReservations':[]}
    def test_bu02_executes_unchanged_topology_with_extra_absence_reads(self):
        result=self.run_guard();self.assertFalse(result['deferred_runtime_consumer_check']);self.assertEqual(result['logging']['flow_logs'],0)
        self.assertIn('eks/terraform.tfstate',self.loads)
    def test_bu03_subscription_and_reservation_exact_retained_contract(self):
        self.add_logging();result=self.run_guard();self.assertEqual(result['logging'],{'flow_logs':1,'resolver_associations':1,'subnet_reservations':1})
    def test_iam_s3_kms_cloudwatch_never_allowed_in_vpc_state(self):
        for kind in ('aws_iam_policy','aws_s3_bucket','aws_s3_bucket_policy','aws_kms_key','aws_cloudwatch_log_group'):
            with self.subTest(kind=kind):
                state=copy.deepcopy(self.f.state);state['resources'].append(t.resource(kind,'foreign','private-id'))
                with self.assertRaises(g.SafeError):g.validate_state(self.f.context,state,upstream_states=self.upstream)
    def test_retained_storage_identity_outputs_protection_and_configuration(self):
        self.add_logging();valid=copy.deepcopy(self.upstream)
        for mutation in ('missing','wrong-output','wrong-bucket','force-destroy','extra-type'):
            self.upstream=copy.deepcopy(valid)
            state=self.upstream[g.LOG]['state']
            if mutation=='missing':state['resources'].pop()
            elif mutation=='wrong-output':state['outputs']['network_logs_bucket_arn']['value']='arn:aws:s3:::foreign'
            elif mutation=='wrong-bucket':state['resources'][0]['instances'][0]['attributes']['bucket']='foreign'
            elif mutation=='force-destroy':next(row for row in state['resources'] if row['type']=='aws_s3_bucket')['instances'][0]['attributes']['force_destroy']=True
            elif mutation=='extra-type':state['resources'].append(t.resource('aws_iam_role','unknown','unknown'))
            with self.subTest(mutation=mutation),self.assertRaises(g.SafeError):g.validate_state(self.f.context,self.f.state,upstream_states=self.upstream)
    def test_retained_config_must_preserve_encryption_versioning_and_objects(self):
        self.add_logging();valid=copy.deepcopy(self.upstream)
        mutations=[('aws_s3_bucket_ownership_controls','rule',[{'object_ownership':'ObjectWriter'}]),
                   ('aws_s3_bucket_server_side_encryption_configuration','rule',[{'apply_server_side_encryption_by_default':[{'sse_algorithm':'aws:kms'}]}]),
                   ('aws_s3_bucket_public_access_block','block_public_acls',False),
                   ('aws_s3_bucket_versioning','versioning_configuration',[{'status':'Suspended'}]),
                   ('aws_s3_bucket_lifecycle_configuration','rule',[{'status':'Enabled','expiration':[{'days':1}]}]),
                   ('aws_s3_bucket_lifecycle_configuration','rule',[{'status':'Enabled','noncurrent_version_expiration':[{'noncurrent_days':1}]}]),
                   ('aws_s3_bucket_policy','policy','{"Statement":[]}')]
        for kind,field,value in mutations:
            self.upstream=copy.deepcopy(valid);state=self.upstream[g.LOG]['state']
            next(row for row in state['resources'] if row['type']==kind)['instances'][0]['attributes'][field]=value
            with self.subTest(kind=kind,field=field),self.assertRaises(g.SafeError):g.storage_contract(self.f.context,self.upstream)

    def test_logging_state_wrong_destination_vpc_or_config_blocks(self):
        self.add_logging()
        for kind,field in [('aws_flow_log','log_destination'),('aws_flow_log','vpc_id'),('aws_route53_resolver_query_log_config','destination_arn'),('aws_route53_resolver_query_log_config_association','resolver_query_log_config_id'),('aws_route53_resolver_query_log_config_association','resource_id')]:
            state=copy.deepcopy(self.f.state);next(r for r in state['resources'] if r['type']==kind)['instances'][0]['attributes'][field]='foreign'
            with self.subTest(kind=kind,field=field),self.assertRaises(g.SafeError):g.validate_state(self.f.context,state,upstream_states=self.upstream)
    def test_logging_is_not_allowed_without_retained_state(self):
        self.add_logging();self.upstream[g.LOG]['state']=None
        with self.assertRaises(g.SafeError):self.run_guard()
    def test_live_unknown_flow_log_resolver_or_reservation_blocks(self):
        self.add_logging();baseline=copy.deepcopy(self.f.responses)
        for operation,field,idfield in [('describe-flow-logs','FlowLogs','FlowLogId'),('list-resolver-query-log-config-associations','ResolverQueryLogConfigAssociations','Id'),('get-subnet-cidr-reservations','SubnetIpv4CidrReservations','SubnetCidrReservationId')]:
            self.f.responses=copy.deepcopy(baseline);service='route53resolver' if operation.startswith('list-') else 'ec2'
            self.f.responses[(service,operation)][field][0][idfield]='foreign'
            with self.subTest(operation=operation),self.assertRaises(g.SafeError):self.run_guard()
    def test_flow_inventory_covers_subnets_and_service_enis(self):
        self.run_guard()
        args=next(args for service,operation,args in self.f.calls if operation=='describe-flow-logs')
        filter_arg=args[args.index('--filter')+1]
        self.assertIn(t.VPC,filter_arg);self.assertIn(t.SUBNET,filter_arg);self.assertIn(t.NAT_ENI,filter_arg)
        self.f.responses[('ec2','describe-flow-logs')]['FlowLogs']=[{'FlowLogId':'fl-unknown','ResourceId':t.SUBNET}]
        with self.assertRaises(g.SafeError):self.run_guard()

    def test_live_wrong_owner_or_destination_blocks(self):
        self.add_logging();response=self.f.responses[('route53resolver','list-resolver-query-log-configs')]['ResolverQueryLogConfigs'][0]
        for field,value in [('OwnerId','999999999999'),('DestinationArn','arn:aws:s3:::foreign/dns/'),('Status','DELETING'),('ShareStatus','SHARED_BY_ME')]:
            old=response[field];response[field]=value
            with self.subTest(field=field),self.assertRaises(g.SafeError):self.run_guard()
            response[field]=old
    def test_incomplete_or_denied_extra_reads_block(self):
        for key in [('ec2','describe-flow-logs'),('route53resolver','list-resolver-query-log-config-associations'),('ec2','get-subnet-cidr-reservations')]:
            old=self.f.responses[key]
            for response in ({**old,'NextToken':'next'}, {}, g.SafeError('Read denied.')):
                self.f.responses[key]=response
                with self.subTest(key=key),self.assertRaises(g.SafeError):self.run_guard()
            self.f.responses[key]=old
    def test_partial_down_remaining_log_ids_use_original_scope(self):
        self.add_logging();original=g.normalize_resources(self.f.state)
        self.f.state['resources']=[r for r in self.f.state['resources'] if r['type']=='aws_route53_resolver_query_log_config_association']
        rows=g.validate_state(self.f.context,self.f.state,expected_resources=original,upstream_states=self.upstream)
        self.assertEqual(len(rows),1)
    def test_plan_ensures_log_destination_contract_with_unknown_new_vpc_ids(self):
        self.add_logging();rows=g.managed_resources(self.f.state)
        planned=[{'address':r['address'],'mode':'managed','type':r['type'],'values':r['values']} for r in rows]
        plan={'planned_values':{'root_module':{'resources':planned}}}
        g.validate_plan_contracts(self.f.context,plan,self.upstream)
        next(r for r in planned if r['type']=='aws_flow_log')['values']['log_destination']='arn:aws:s3:::wrong/flow/'
        with self.assertRaises(g.SafeError):g.validate_plan_contracts(self.f.context,plan,self.upstream)
    def test_unregistered_live_dependents_block_at_plan_and_apply(self):
        self.deps['eks/terraform.tfstate']={'state':t.state_of([t.resource('aws_eks_cluster','this','eks-private')]),'fingerprint':{'exists':True,'version':'eks1'}}
        for stage in ('plan','apply'):
            with self.subTest(stage=stage),self.assertRaises(g.SafeError):self.run_guard(stage)
    def test_retained_storage_fingerprint_includes_absence_at_bu02(self):
        self.assertEqual(g.read_upstreams(self.workspace,self.f.context,load_state=self.reader),{g.LOG:{'state':None,'fingerprint':{'exists':False}}})
    def test_live_transit_cannot_be_deferred_at_apply(self):
        self.f.context['selected_roots']=[g.VPC,g.PEER,g.TRANSIT]
        self.deps['network/transit/terraform.tfstate']={'state':t.state_of([t.resource('aws_ec2_transit_gateway','this','tgw-1234')]),'fingerprint':{'exists':True,'version':'transit1'}}
        with self.assertRaises(g.SafeError):self.run_guard('apply')
    def test_selected_later_consumer_requires_exact_descriptor_proof_and_never_defers_apply(self):
        eks='terraform/environments/dev/eks';self.f.context['selected_roots']=[g.VPC,eks]
        self.deps['eks/terraform.tfstate']={'state':t.state_of([t.resource('aws_eks_cluster','this','owned-cluster')]),'fingerprint':{'exists':True,'version':'eks1'}}
        proof={eks:{'descriptor':{'manifest_sha':'a'*64},'managed_count':1}}
        consumer=SimpleNamespace(selected_descriptors=Mock(return_value={eks:{'exact':'descriptor'}}),prove_consumers=Mock(return_value=proof))
        real_load=g.load
        def loader(name,file):return consumer if file=='network-consumer-proof.py' else real_load(name,file)
        with patch.object(g,'load',side_effect=loader),patch.object(g.v,'inventory_consumers',return_value={}) as inventory:
            result=self.run_guard();self.assertTrue(result['deferred_runtime_consumer_check']);self.assertEqual(result['deferred_consumers'],proof)
            self.assertIsNone(result['selected_transit']);inventory.assert_not_called();consumer.prove_consumers.assert_called_once()
            self.assertEqual(set(consumer.prove_consumers.call_args.args[2]),{eks})
            with self.assertRaises(g.SafeError):self.run_guard('apply')
            consumer.prove_consumers.assert_called_once()

    def test_peer_runtime_full_guard_includes_unknown_logging_consumers(self):
        state=t.state_of([
            t.resource('aws_vpc','peer',t.VPC,owner_id=t.ACCOUNT,default_network_acl_id=t.ACL,default_route_table_id=t.RT),
            t.resource('aws_default_security_group','peer',t.SG,vpc_id=t.VPC),
            t.resource('aws_subnet','peer',t.SUBNET,index='ap-northeast-2a',vpc_id=t.VPC),
            t.resource('aws_route_table','peer','rtb-1123456789abcdef0',index='ap-northeast-2a',vpc_id=t.VPC),
            t.resource('aws_route_table_association','peer','rtbassoc-1123456789abcdef0',index='ap-northeast-2a',subnet_id=t.SUBNET,route_table_id='rtb-1123456789abcdef0'),
        ])
        context={**self.f.context,'root':g.PEER,'backend':{**self.f.context['backend'],'key':'network/peer/terraform.tfstate'}}
        for operation,field in [('describe-internet-gateways','InternetGateways'),('describe-nat-gateways','NatGateways'),('describe-network-interfaces','NetworkInterfaces')]:
            self.f.responses[('ec2',operation)][field]=[]
        self.f.responses[('ec2','describe-route-tables')]['RouteTables']=[{'RouteTableId':identity,'VpcId':t.VPC,'OwnerId':t.ACCOUNT,'Routes':[{'GatewayId':'local'}],'Associations':[]} for identity in (t.RT,'rtb-1123456789abcdef0')]
        def run():return g.guard_destroy(self.workspace,context,state,t.plan_of(state),expected_resources=g.normalize_resources(state),upstream_states={},stage='apply',aws_call=self.f.aws,load_state=self.reader)
        self.assertEqual(run()['vpc_id'],t.VPC)
        self.f.responses[('ec2','describe-flow-logs')]['FlowLogs']=[{'FlowLogId':'fl-foreign','ResourceId':t.VPC}]
        with self.assertRaises(g.SafeError):run()

    def test_selected_transit_plan_records_deferral_but_apply_uses_full_guard(self):
        topology_tests=load('selected_transit_fixtures','test_network_topology_guard.py')
        fx=topology_tests.Fixture();self.f.state=fx.upstream[g.VPC]
        self.f.context['selected_roots']=[g.VPC,g.PEER,g.TRANSIT]
        self.deps['network/transit/terraform.tfstate']={'state':fx.state,'fingerprint':{'exists':True,'version':'transit1'}}
        self.deps['network/peer/terraform.tfstate']={'state':fx.upstream[g.PEER],'fingerprint':{'exists':True,'version':'peer1'}}
        record=dict(root=g.TRANSIT,phase='paused',operation='down',request_run='1',request_attempt='1',workflow_sha='a'*40,
                    repository_id='17',account=t.ACCOUNT,bucket='private-state',region='ap-northeast-2',snapshot_sha='a'*40,generation='1-1',
                    original_resources=fx.original,original_state_identity={'lineage':'private','serial':2})
        real_load=g.load
        def fake_load(name,file):
            if file=='lifecycle-state.py':return SimpleNamespace(read_json=Mock(return_value=(record,{'exists':True,'version':'marker1'})))
            if file=='saved-plan.py':return SimpleNamespace(Store=Mock())
            return real_load(name,file)
        def aws(service,operation,*args):
            if operation in ('describe-flow-logs','get-subnet-cidr-reservations','list-resolver-query-log-config-associations','list-resolver-query-log-configs'):
                return self.f.aws(service,operation,*args)
            return fx.aws(service,operation,*args)
        with patch.object(g,'load',side_effect=fake_load),patch.object(g.v,'inventory_consumers',return_value={}) as inventory:
            result=g.guard_destroy(self.workspace,self.f.context,self.f.state,t.plan_of(self.f.state),expected_resources=g.normalize_resources(self.f.state),
                                   upstream_states=self.upstream,stage='plan',aws_call=aws,load_state=self.reader)
            self.assertTrue(result['deferred_runtime_consumer_check']);self.assertTrue(result['selected_transit']['requires_unfiltered_apply_recheck'])
            inventory.assert_not_called()
            # Unknown consumer State still blocks even when transit is selected.
            self.deps['eks/terraform.tfstate']={'state':t.state_of([t.resource('aws_eks_cluster','this','unknown')]),'fingerprint':{'exists':True,'version':'eks1'}}
            with self.assertRaises(g.SafeError):
                g.guard_destroy(self.workspace,self.f.context,self.f.state,t.plan_of(self.f.state),expected_resources=g.normalize_resources(self.f.state),
                                upstream_states=self.upstream,stage='plan',aws_call=aws,load_state=self.reader)
            del self.deps['eks/terraform.tfstate']
            self.deps['network/transit/terraform.tfstate']={'state':t.state_of([]),'fingerprint':{'exists':True,'version':'transit2'}}
            result=g.guard_destroy(self.workspace,self.f.context,self.f.state,t.plan_of(self.f.state),expected_resources=g.normalize_resources(self.f.state),
                                   upstream_states=self.upstream,stage='apply',aws_call=aws,load_state=self.reader)
            self.assertFalse(result['deferred_runtime_consumer_check']);inventory.assert_called_once()

    def test_vpc_absence_alone_cannot_hide_original_orphan_eip(self):
        original=g.normalize_resources(self.f.state)
        keys={'describe-vpcs':'Vpcs','describe-addresses':'Addresses','describe-internet-gateways':'InternetGateways',
              'describe-nat-gateways':'NatGateways','describe-subnets':'Subnets','describe-route-tables':'RouteTables',
              'describe-security-groups':'SecurityGroups','describe-network-acls':'NetworkAcls'}
        def absent(service,operation,*args):
            return {'Account':t.ACCOUNT} if operation=='get-caller-identity' else {keys[operation]:[]}
        result=g.verify_absent(self.f.context,original,aws_call=absent)
        self.assertEqual(result['original_identity_absence']['aws_eip'],1)
        def orphan(service,operation,*args):
            if operation=='describe-addresses':return {'Addresses':[{'AllocationId':t.EIP,'Domain':'vpc'}]}
            return absent(service,operation,*args)
        with self.assertRaises(g.SafeError):g.verify_absent(self.f.context,original,aws_call=orphan)
        def denied(service,operation,*args):
            if operation=='describe-addresses':raise g.SafeError('Read denied.')
            return absent(service,operation,*args)
        with self.assertRaises(g.SafeError):g.verify_absent(self.f.context,original,aws_call=denied)

    def test_destroy_plan_added_resource_or_replacement_blocks(self):
        self.add_logging();plan=t.plan_of(self.f.state);plan['resource_changes'][0]['change']['actions']=['delete','create']
        with self.assertRaises(g.SafeError):g.guard_destroy(self.workspace,self.f.context,self.f.state,plan,expected_resources=g.normalize_resources(self.f.state),upstream_states=self.upstream,stage='plan',aws_call=self.f.aws,load_state=self.reader)

if __name__=='__main__':unittest.main()
