"""Prod DB protection transition only. Does not delete DB or authorize Terraform destroy."""
import importlib.util,json,time
IDS=('database-protection-disable','database-protection-restore')
def call(io,c,*args):return json.loads(io.ops.run(['aws','rds',*args,'--region',c['region'],'--output','json']))
def snapshot(io,operation,r,c,store):
    io.require(set(r)<={'source_sha','expires_at','change_request','data_decision' }|{'db_arn','db_resource_id','retained_snapshot_arn','retain_all_s3_and_backups'},'Unknown request fields; plaintext credentials and arbitrary commands forbidden')
    io.require(operation in IDS and c['environment']=='prod','Protection transition is registered Prod only')
    wanted=operation.endswith('restore')
    io.require(r['data_decision']==('restore-production-db-deletion-protection' if wanted else 'approved-production-decommission-protection-transition'),'Exact consequential transition approval required')
    spec=importlib.util.spec_from_file_location('protection_state',io.ops.shared_file('vpc-lifecycle-guard.py'));module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    saved=module.VersionedStateReader(c['state_bucket'],c['account_id'],c['region'])('data/terraform.tfstate');contract=saved['state']['outputs']['data_contract']['value']
    io.require(contract['environment']=='prod' and contract['account_id']==c['account_id'],'Prod State identity mismatch')
    db=call(io,c,'describe-db-instances','--db-instance-identifier',contract['database']['identifier'])['DBInstances'][0]
    io.require(db['DBInstanceArn']==r['db_arn'] and db['DbiResourceId']==r['db_resource_id'] and db['DBInstanceStatus']=='available','Production DB creation identity/readiness differs')
    io.require(db['DeletionProtection'] is (not wanted),'Expected original protection state differs')
    io.require(db['StorageEncrypted'] and db.get('KmsKeyId') and db['BackupRetentionPeriod']>=7,'Encrypted DB with retained automated backups required')
    io.require(not db.get('PendingModifiedValues'),'Concurrent RDS modification must finish first')
    snapshot=None
    if not wanted:
        snapshot=call(io,c,'describe-db-snapshots','--db-snapshot-identifier',r['retained_snapshot_arn'])['DBSnapshots'][0]
        io.require(snapshot['DBSnapshotArn']==r['retained_snapshot_arn'] and snapshot['DbiResourceId']==db['DbiResourceId'] and snapshot['Status']=='available' and snapshot['Encrypted'] and snapshot['KmsKeyId']==db['KmsKeyId'],'Exact available encrypted retained snapshot required')
        io.require(r['retain_all_s3_and_backups'] is True,'Explicit S3 and backup retention decision required')
    return {'state':saved['fingerprint'],'identifier':db['DBInstanceIdentifier'],'db_arn':db['DBInstanceArn'],'resource_id':db['DbiResourceId'],'from':db['DeletionProtection'],'to':wanted,'kms_key':db['KmsKeyId'],'backup_retention_days':db['BackupRetentionPeriod'],'snapshot_arn':snapshot['DBSnapshotArn'] if snapshot else None,'region':c['region'],'destroy_authorized':False}

def apply(io,operation,target,r,mark):
    io.require(operation in IDS,'Unknown protection transition')
    c={'region':target['region']};db=call(io,c,'describe-db-instances','--db-instance-identifier',target['identifier'])['DBInstances'][0]
    io.require(db['DBInstanceArn']==target['db_arn'] and db['DbiResourceId']==target['resource_id'] and db['DeletionProtection'] is target['from'] and not db.get('PendingModifiedValues'),'DB changed since review')
    mark('active',target)
    call(io,c,'modify-db-instance','--db-instance-identifier',target['identifier'],'--deletion-protection' if target['to'] else '--no-deletion-protection','--apply-immediately')
    for _ in range(60):
        db=call(io,c,'describe-db-instances','--db-instance-identifier',target['identifier'])['DBInstances'][0]
        io.require(db['DbiResourceId']==target['resource_id'],'DB replaced during protection change')
        if db['DeletionProtection'] is target['to']:
            result={'db_arn':target['db_arn'],'resource_id':target['resource_id'],'deletion_protection':target['to'],'destroy_authorized':False};mark('idle',dict(target,result=result));return result
        time.sleep(5)
    raise io.h.SafeError('Protection observation timeout; exact DB marker remains for reviewed reconciliation')
