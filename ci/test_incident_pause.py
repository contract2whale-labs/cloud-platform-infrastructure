import copy
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parent

def load(name,file):
    spec=importlib.util.spec_from_file_location(name,HERE/file);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
c=load('incident_control_test','lifecycle-state.py')
f=load('incident_control_fixtures','test_vpc_lifecycle.py')

class IncidentPauseTests(unittest.TestCase):
    def setUp(self):
        self.store=f.Store();self.ctx={'root':'terraform/environments/dev/network/vpc','repository_id':'17','account':'123456789012','backend':{'bucket':'private-state','region':'ap-northeast-2'}}
        self.record={'schema':1,'owner':'aws-fixed-operations','phase':'active','repository_id':'17','account':'123456789012','bucket':'private-state','region':'ap-northeast-2','environment':'dev','generation':'10-1','operation':'limit-nodegroup','target':{'name':'exact-target'},'request_context':{'source_sha':'a'*40}}
        self.key=c.incident_marker_key('17','dev')
    def write(self,record):c.update(self.store,self.key,record,{'exists':False})
    def test_missing_incident_allows_normal_precheck(self):c.assert_incident_clear(self.store,self.ctx)
    def test_idle_allows_both_fixed_owners(self):
        for owner in ('aws-fixed-operations','kubernetes-fixed-operations'):
            with self.subTest(owner=owner):
                self.store=f.Store();self.write({**self.record,'owner':owner,'phase':'idle'});c.assert_incident_clear(self.store,self.ctx)
    def test_active_and_recovery_required_always_block(self):
        for phase in ('active','recovery-required'):
            self.store=f.Store();self.write({**self.record,'phase':phase})
            with self.subTest(phase=phase),self.assertRaises(Exception):c.assert_incident_clear(self.store,self.ctx)
    def test_unknown_owner_or_target_or_schema_is_not_clear(self):
        for field,value in [('owner','arbitrary'),('phase','complete'),('account','999999999999'),('environment','prod'),('schema',True),('generation','bad')]:
            self.store=f.Store();self.write({**self.record,field:value})
            with self.subTest(field=field),self.assertRaises(Exception):c.assert_incident_clear(self.store,self.ctx)
    def test_denied_read_is_not_absence(self):
        with patch.object(self.store,'state',side_effect=PermissionError('denied')):
            with self.assertRaises(PermissionError):c.assert_incident_clear(self.store,self.ctx)
    def test_prod_uses_separate_exact_marker(self):
        ctx=copy.deepcopy(self.ctx);ctx['root']='terraform/environments/prod/data'
        record={**self.record,'environment':'prod'};key=c.incident_marker_key('17','prod')
        c.update(self.store,key,record,{'exists':False})
        with self.assertRaises(Exception):c.assert_incident_clear(self.store,ctx)
    def test_normal_path_stops_before_course_or_graph_reads(self):
        self.write(self.record)
        with patch.object(c,'affected',side_effect=AssertionError('must not reach graph')):
            with self.assertRaises(Exception):c.assert_normal_allowed(self.store,self.ctx,'.')

if __name__=='__main__':unittest.main()
