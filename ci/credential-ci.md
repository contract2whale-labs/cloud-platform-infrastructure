# Source-backed credential and database operations

Install the shared `gitops-ci-proposal` fixed-operation workflow and helpers before dispatch. These operations use its exact private JSON action plan, protected Environment approval, same-action apply, current-main checks, State/private-API binding, single global concurrency and durable incident marker. They are executable source additions, but no live deployment was performed here.

## Managed queue

`managed-queue-setup` is available for Dev and Prod. Register `source_sha`, `script_sha256`, `credential_run_id` (new UUID), the actual `pod_uid`, `cluster_arn`, and `data_decision=create-temporary-admin-topics-acls-and-recoverable-cleanup` in the existing protected `operations/requests.json` operation entry. Common expiry/change request fields are still required. Source SHA is the committed infrastructure revision containing the refactored original `setup-managed-topics.sh`, not this proposal's filesystem path. Obtain the SHA from Git; obtain Pod UID with a read-only Kubernetes get and cluster ARN from `queue_managed_contract`.

The reviewed action includes temporary SCRAM admin creation/association, the original bounded topic/ACL setup and smoke check, config removal, disassociation and **seven-day recoverable deletion scheduling**. Both source editions and Part3 now use that window. There is no force deletion. An active failure marker is not permission to retry; preserve the original UUID and inspect the exact Secret, association and Pod configuration. Secret metadata is retained in a private completion receipt; password and raw output are not published. Temporary credentials require the protected apply identity to have the explicitly reviewed temporary-name/KMS/MSK scope. Do not broaden the general Terraform role.

## Database bootstrap

`database-bootstrap` uses the original BU13 Job entrypoint `/opt/contract2whale/operator/bootstrap.sh`. It derives its immutable ConfigMap from current versioned `data_contract`, validates the actual RDS ARN/resource ID, master Secret and Secret stage metadata, ServiceAccount UID and Pod Identity association, and authenticates the versioned signed/SPDX operator publication receipt. It never accepts SQL, shell, credentials or SecretString in the request.

Request fields: `bootstrap_run_id`, `job_name` and `configmap_name` both `database-bootstrap-<UUID>`, `db_arn`, `db_resource_id`, `serviceaccount_uid`, `association_id`, `operator_role_arn`, `operator_image` (full digest reference), `operator_source_sha`, `operator_publication_receipt` (`key`, `version`, `sha256`), and `data_decision=bootstrap-reviewed-database-roles-and-secret-stages`. Common source/expiry/change request fields apply. All are metadata, not passwords. Obtain them from real data/identity outputs, the actual API readback and the successful operator-publish receipt; do not copy the lesson's example ARN values.

Protected registration may set `operator_evidence_bucket`; it defaults to the State bucket. `operator_evidence_account` must equal the registered account. Publication prefix is the real `operator-publication/<environment>/<run>/operator-publication.json`; a digest alone does not prove publication. The named bucket must be private/versioned and readable by the plan/apply roles.

The original bootstrap script's AWSPENDING → DB role password/login → AWSCURRENT ordering remains intact inside the exact image. There is no standalone runner Secret promotion. Job success is bootstrap completion only, not app migration, seed provenance, or an original-data restoration assertion.

Before the first create, a persistent marker is written. If creation was acknowledged, receipts retain exact ConfigMap/Job UIDs; timeout can be resolved with `database-bootstrap-observe`, which only reads those exact identities and clears the marker after success. It never replays credentials. If the create outcome was unknown and no UID was captured, observation refuses adoption; protected identity reconciliation is required. Failed Jobs remain for diagnosis, with no blind retry, forced deletion or raw log publication. Executable example Jobs must not also be synchronized by Argo.

## Production deletion protection

`database-protection-disable` and `database-protection-restore` alter only the exact current production database's deletion protection. Disable requires an available encrypted same-DB/same-KMS retained snapshot and at least seven days of automated-backup retention. Register `db_arn`, `db_resource_id`, `retained_snapshot_arn`, `retain_all_s3_and_backups=true`, and the explicit disable data decision shown in the module. Restore uses `restore-production-db-deletion-protection`.

Neither operation deletes the database, changes backup retention, or authorizes a saved destroy plan. Existing Prod Terraform safeguards remain a separate requirement. Cancellation uses a separately reviewed restore operation; the adapter does not silently bypass the course's Prod guard.

## Offline validation

Use `python -m unittest discover -s ci/gitops/operations/tests`. Tests simulate API outcomes; passing tests do not establish live IAM, Pod Identity, provider execution or database recovery.

## BU16 T13 complete producer ACL drill

`producer-acl-cycle` is Dev-only and needs no external temporary credential issuer.
Its reviewed request contains common source/expiry/change fields plus:
`experiment_id` UUID, actual `pod_uid`, `cluster_arn`,
`setup_script_sha256`, `hold_seconds` (30–120), and
`data_decision=bounded-one-producer-deny-restore-and-seven-day-admin-cleanup`.
The approved source revision contains the existing refactored managed setup helper;
the fixed adapter shares its actual State, cluster, name, Pod and KMS contract.

The exact action issues a real UUID-versioned temporary admin Secret, records the
AWS acknowledgement, associates it with that MSK cluster and writes its credential
only through private stdin to the original Pod. Passwords never appear in plans,
requests, markers, receipts or public logs. After authentication, the handler reads
the actual complete ACL set and validates the original source-defined producer and
reader boundary before any fault. It records this baseline durably, verifies a
baseline synthetic trace, adds exactly one LITERAL DENY WRITE tuple for
`User:tempo-distributor` on the actual epoch-2 topic, and verifies the resulting set
is precisely baseline plus that tuple. No existing ACL is replaced.

Within the same approved action, fixed digest-pinned curl Pods send/query baseline,
fault and recovered trace IDs; the original fault ID is queried again after
recovery. Only query HTTP 404 is retried. HTTP/authentication/transport errors are
never absence. The original distributor Deployment UID and bounded post-injection
logs provide an independently recorded authorization-error observation. Receipts
separate accepted sends, exact-ID query results, ACL restoration, and cleanup.
A missing fault trace does not claim permanent data loss, nor does ACL restoration
alone claim service recovery.

Finally, the exact complete original ACL set must be restored before credentials
are retired. Each probe is deleted using its captured UID/resourceVersion and its
absence is observed. The admin configuration is removed, the original MSK
association set is restored, and the temporary Secret is scheduled for seven-day
recoverable deletion with acknowledgement/readback. There is no force deletion or
permanent-absence claim. Unknown creation outcomes or unrelated ACL drift retain a
recovery marker and stop. `producer-acl-recover` requires the same original UUID,
cluster and Pod UID; it reads only the acknowledged exact Secret version, never
issues a new credential or reinjects the fault. Recovery must preserve baseline
ACLs and exact probe identities. Concurrent out-of-band operators must be excluded;
Kafka ACL commands and Kubernetes exec do not provide cross-service atomicity.

The original lesson and Part3 now dispatch this operation once and read its real
private receipt, rather than fabricating external issuance evidence.

## BU10B S3 endpoint policy recovery

`s3-endpoint-policy-recover` is Dev-only. It reads the actual source-owned S3 Gateway
endpoint from network/vpc State and the policy owner from observability State.
Place the reviewed previous JSON in the fixed committed
`operations/requests/s3-endpoint-recovery-policy.json`. Request its exact
`policy_sha256`, endpoint/VPC IDs and `reconcile_source_change`, with
`data_decision=restore-reviewed-s3-gateway-endpoint-policy`. Wildcards require
`policy_expansion_approved=true` explicitly. The saved action binds the entire live
old policy and route-table set; apply changes only that exact endpoint policy and
verifies the result. It does not reset networking, modify routes, or grant a generic
EC2 mutation endpoint. Follow with the recorded source-reconciliation PR and fresh
ordinary Terraform plan. A policy transition is a security-sensitive protected
approval, not an automatic response to a failed image pull.

## Bootstrap cleanup

`database-bootstrap-cleanup` authenticates the successful original bootstrap or
observe receipt and its two exact created identities. Request common metadata,
`bootstrap_run_id`, `creation_receipt`, and
`data_decision=remove-completed-bootstrap-job-and-configmap`. Only the completed
Job and its ConfigMap are deleted with UID/resourceVersion conditions. Partial
cleanup retains a per-UID attempted-delete marker; a later approved request can
observe original attempted absence without adopting replacement objects. Argo
prune is not used. Database, Secrets and separately created diagnostic Jobs remain
outside this operation.
