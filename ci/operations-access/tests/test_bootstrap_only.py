import copy,importlib.util,json,pathlib,unittest
BASE=pathlib.Path(__file__).resolve().parents[1]
s=importlib.util.spec_from_file_location('early_access',BASE/'access.py');m=importlib.util.module_from_spec(s);s.loader.exec_module(m)

class BootstrapOnlyAccess(unittest.TestCase):
    def config(self):
        c=json.loads((BASE/'examples/dev.json').read_bytes());c.update(bootstrap_only=True,application_names=[]);return c
    def test_explicit_empty_bootstrap_compiles_without_app_mutations(self):
        c=self.config();m.validate(c);items=m.rbac(c)
        for obj in items:
            for rule in obj.get('rules',[]):
                if 'applications' in rule.get('resources',[]):
                    self.assertFalse(set(rule['verbs']) & set(m.MUTATE))
                    self.assertNotEqual(rule.get('resourceNames'),[])
        admission=next(x for x in m.admission(c) if x['kind']=='ValidatingAdmissionPolicy' and x['metadata']['name']=='cp-argo-object-boundary-dev')
        self.assertTrue(admission['spec']['validations'][0]['expression'].endswith(' in []'))
        self.assertTrue(any(x['kind']=='Namespace' and x['metadata']['name']=='course-node-probes' for x in items))
    def test_empty_registration_requires_explicit_flag(self):
        c=self.config();c.pop('bootstrap_only')
        with self.assertRaises(ValueError):m.validate(c)
        for bad in ('true',1,None):
            c=self.config();c['bootstrap_only']=bad
            with self.assertRaises(ValueError):m.validate(c)
    def test_bootstrap_only_cannot_hide_later_applications(self):
        c=self.config();c['application_names']=['platform-namespaces-dev']
        with self.assertRaises(ValueError):m.validate(c)
        c['bootstrap_only']=False;m.validate(c)

    def test_velero_lifecycle_access_is_exact_in_dev_and_prod(self):
        from test_access import allows
        for environment in ('dev','prod'):
            c=self.config();c['environment']=environment;items=m.rbac(c);group='cp:'+environment+':lifecycle-destroy'
            for namespace in ('backup-probe','backup-probe-restored'):
                self.assertTrue(allows(items,group,'create','','pods/exec',namespace,'writer'))
                self.assertTrue(allows(items,group,'delete','','pods',namespace,'writer'))
                self.assertTrue(allows(items,group,'delete','','persistentvolumeclaims',namespace,'data'))
                self.assertFalse(allows(items,group,'create','','pods/exec',namespace,'foreign'))
                self.assertFalse(allows(items,group,'delete','','persistentvolumeclaims',namespace,'foreign'))
            for resource,name in [('backups','platform-storage-probe'),('restores','platform-storage-probe'),('schedules','platform-daily'),('backupstoragelocations','default'),('volumesnapshotlocations','default')]:
                self.assertTrue(allows(items,group,'patch','velero.io',resource,'velero',name))
                self.assertFalse(allows(items,group,'patch','velero.io',resource,'velero','foreign'))
                for verb in ('create','delete'):self.assertFalse(allows(items,group,verb,'velero.io',resource,'velero',name))
            self.assertTrue(allows(items,'cp:'+environment+':incident-plan','get','velero.io','backups','velero','platform-storage-probe'))
    def test_refresh_marker_is_only_writable_by_protected_bootstrap(self):
        c=self.config()
        for role in m.ROLES:
            documents=m.policies(c,role)
            writable=[resource for rules in documents.values() for statement in rules if statement.get('Effect')=='Allow' and 's3:PutObject' in statement['Action'] for resource in statement['Resource'] if 'operation-access/' in resource]
            self.assertEqual(any(resource.endswith('/access-refresh.json') for resource in writable),role=='gitops-bootstrap')

if __name__=='__main__':unittest.main()
