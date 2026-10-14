import copy,unittest
from runtime_guard import validate_plan,Blocked
D={'environment':'dev','writers_quiesced':True,'retained_verified':True,'owner_cleanup_verified':True,'completion_sha256':'a'*64,'mode':'seed','seed_reset_approved':True,'fixture_sha256':'b'*64,'migration_sha256':'c'*64,'seed_receipt_sha256':'d'*64,'media_consistency_verified':True}
A='module.component.aws_db_instance.data'
O={A:{'id':'db-original','identifier':'course-db'}}
P={'resource_changes':[{'mode':'managed','address':A,'type':'aws_db_instance','change':{'actions':['delete'],'before':{'id':'db-original','deletion_protection':False,'delete_automated_backups':False}}}]}
class Runtime(unittest.TestCase):
 def test_exact_down(self):self.assertEqual(validate_plan('data','down',P,D,O)['changed'],[A])
 def test_malformed_and_protected_fail(self):
  for field,val in [('environment','prod'),('mode','restore'),('media_consistency_verified',False),('seed_reset_approved',False)]:
   d=dict(D);d[field]=val
   with self.assertRaises(Blocked):validate_plan('data','down',P,d,O)
  for field,val in [('deletion_protection',True),('delete_automated_backups',True),('id','another-db')]:
   p=copy.deepcopy(P);p['resource_changes'][0]['change']['before'][field]=val
   with self.assertRaises(Blocked):validate_plan('data','down',p,D,O)
 def test_incomplete_duplicate_type_spoof(self):
  for p in ({'resource_changes':[]},{'resource_changes':P['resource_changes']*2}):
   with self.assertRaises(Blocked):validate_plan('data','down',p,D,O)
  p=copy.deepcopy(P);p['resource_changes'][0]['type']='aws_s3_bucket'
  with self.assertRaises(Blocked):validate_plan('data','down',p,D,O)
 def test_known_up_names(self):
  p=copy.deepcopy(P);p['resource_changes'][0]['change']={'actions':['create'],'after':{'identifier':'course-db'}}
  self.assertEqual(validate_plan('data','up',p,D,O)['changed'],[A])
  p['resource_changes'][0]['change']['after']['identifier']='new-name'
  with self.assertRaises(Blocked):validate_plan('data','up',p,D,O)
if __name__=='__main__':unittest.main()
