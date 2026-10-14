# Finite course lifecycle obligations

This is a static integration map, not activation by JSON or permission to execute an arbitrary hook. No live AWS, Kubernetes or GitHub mutation was used to validate this implementation.

## Registered semantic execution provider

Install `ci/lifecycle-obligations.py` alongside `saved-plan.py`, `lifecycle-state.py`, `vpc-lifecycle-guard.py`, and `eks-lifecycle.py`.

Register the five exact members of `HOOKS` as `<environment>-semantic-v1`, using this module's `run(start|plan|verify|apply)`. Add these same IDs to central barrier authentication, and delegate their result validation to `validate_result`. The schema is `1`, manifest kind `gitops-lifecycle`, completion kind `gitops-lifecycle-completion`. Action plans contain bounded semantic contracts, never shell text.

The adapter uses the existing protected Down role `gha-infra-<env>-lifecycle-destroy`. Up uses `apply`; the Prod Up `plan` stage alone uses `plan`. Every stage verifies identity, the refreshable profile, trusted dispatch, main SHA, source ancestry and unchanged Terraform/module source. Its independent marker is `ci-lifecycle/<repo>/<environment>/hook-<id>.json`. Plans bind its exact CAS version, generation, source, registry, operation, run/attempt and TTL. Only apply writes a completion receipt after the exact approved action bytes and fresh read-only checks pass.

### Ordering

- `external-log-consumer-drain`: Down before `account-integrations` destruction; Up after that root's restore. The hook follows account-integrations in the forward dependency graph. The retained effective input must be false, or the exact immutable module source must prove the default false. Actual current State must contain no external SQS/notification/consumer-role/alarm resources. The enabled branch fails closed: approximate queue depth is not proof that an external recipient has drained or stopped.
- `out-of-state-pitr-inventory`: Down before data/network destruction; Up after enough prerequisites to read retained evidence. It checks every retained version of the fixed AWS incident marker, not just its latest action. A later SCRAM action cannot hide an earlier PITR clone. Pending or uncertain markers block. Creation and deletion receipts are authenticated against original fixed action plan bytes, repository/account/run, exact RDS ARN and DbiResourceId. Live clone names/IDs must be absent, and the final encrypted snapshot must still match its resource ID and KMS key. Tags only identify unknown resources to reject; they never authorize deletion.
- `incident-quiescence-and-baseline`: use as an early Down preflight; every provider also enforces the shared incident marker. Its claim is fixed recovery-owner idleness, not generic Kubernetes object cleanup. Object cleanup is owned by the corresponding authenticated GitOps/operation hook.
- `reviewed-cleanup` and `service-absence-audit`: Down after all disposable Terraform roots; place before those roots in the forward graph. These are Up contract checks before reconstruction, not a claim that future Up steps are already complete. Down audits require every root in the completed ordered prefix, exact per-root completion markers and private receipts, and unchanged post-completion State versions. Both preserve each provider's bounded evidence. In particular, registered ordinary roots prove exact empty managed State, not full cloud absence. Output explicitly sets account-wide absence to false.

Retained roots do not enter the cleanup audit's disposable root list. All S3, retained identities, keys, source assets and backups can continue to incur charges.

## Provider aliases, not duplicate execution

`ALIASES` is an explicit code-level contract:

- `minimum-argo-bootstrap` and `prod-minimum-argo-bootstrap` are provided by selected `platform-core`. Both GitOps wrappers bind a fresh EKS/relay State pair and validate the current cluster incarnation's protected bootstrap receipt with checkpoint generation, source, registered chart/toolchain and access-config digests. Do not create a second bootstrap process or synthesize a successful no-op receipt.
- `app-auth-provision-and-securitypolicy` is provided by selected `platform-gateway` plus retention of the whole `platform/app-auth` root. Its static gateway group includes `gateway-auth`. Retention keeps Cognito identity/client/domain and verifier Secret identity; ordinary Up must not reprovision users or rotate credentials.

Central alias validation must require the concrete provider hook is selected and registered, and each listed retained root is actually in retain mode. The provider's real completion proof is the alias proof. A label in a registry cannot bypass these checks.

## Remaining separate providers

`velero-backup-restore` requires the exact finite storage retirement/retention adapter, described with its implementation. It must not replay every backup/restore exercise on Up.

`prod-edge-publication` is not proven by the current ordinary Terraform root completion receipt. That provider proves approved State only. Live CloudFront/VPC-origin/ACM/DNS/TLS publication needs a separate bounded readback; do not alias it to generic apply success.

## Tests

`python -m unittest discover -s ci -p test_lifecycle_obligations.py -v`

The tests are offline, injected-provider verification. They do not establish deployed identities, IAM access, real source registration, cloud absence, or successful end-to-end lifecycle execution.

## Exact Velero provider

Install `velero-lifecycle.py` and register `hook:velero-backup-restore` separately, using `run(start|plan|verify|apply)` and its own `validate_result`. Put it after `platform-operations` in the forward graph, so Down retires synthetic storage before chart/controller cleanup. The adapter uses the same schema-1 manifest/completion envelope and nonexpiring independent CAS. Its manifest also fixes fresh Kubernetes resource versions; resource-version drift requires a new reviewed plan.

Initial Down authenticates the existing protected fixed-operation `velero-lab-restore` receipt and its actual immutable incident action plan, bound to the current Backup/Restore UIDs/specs. It captures the two exact original/restored Pod+PVC pairs and PVC→PV→EBS identities. Apply checks their contents with existing fixed read commands, preserves metadata through an exact annotation-only Delete=false patch, deletes both writers before either claim using UID/resourceVersion preconditions, then requires actual CSI PV/EBS absence. It never deletes a namespace, PV directly, S3 object, Backup/Restore, or snapshot. Interrupted ownership remains paused; a fresh run may reconcile only exact known outcomes after the prior authenticated run has ended.

The protected residual chain contains only `velero.io/v1` Backup/Restore named platform-storage-probe, paused Schedule platform-daily, and default BackupStorageLocation/VolumeSnapshotLocation. Their metadata hashes are carried into core's authenticated residual contract. The default source uses AWS-plugin EC2 snapshots, not CSI VolumeSnapshot CRs; unknown CSI or DeleteBackupRequest objects block rather than acquiring permission by kind.

Both source and actual live Velero runtime-role policy must protect the exact S3 `backups/backups/platform-storage-probe/*` object prefix and same-account/region snapshot resources with `velero.io/backup=platform-storage-probe`. This is durable protection of retained bytes; it does not claim that an expired Backup CR is a fresh successful restore. Velero v1.18.2 TTL zero selects the default TTL, so the adapter does not fake nonexpiry with ttl:0. Retained S3 objects and EC2 snapshots continue to incur ordinary storage charges. Removing the protection or deleting those retained data requires a separate explicitly approved cleanup.

Up verifies the retained remote snapshot and leaves recreation of the original sample declaration to platform-operations. It does not repeat the completed backup/restore exercise. A subsequent Down authenticates the previous completed lifecycle Up, requires unchanged sample source, and captures only the freshly restored original sample pair. It rejects an unexpected new restored pair or non-synthetic files. This supports repeated lifecycle cycles without pretending the old restore receipt belongs to a new cluster.

Protected fixed `velero_ops.py` and `argo-backup-probe-retire` now support the same exact Dev and Prod scope, preserving their existing approval and source/UID checks.

## Exact pending data-owner handoff

Install `lifecycle-data-handoff.py` alongside the other CI helpers. The basic GitOps wrapper supplies its actual stage through `LIFECYCLE_HOOK_STAGE`; there is no new user input.

The whole Down bundle is planned before any teardown. During that planning, known Grafana/Kafka data therefore still exists. `lifecycle_hooks.plan/verify` may account for it only through selected platform-observability or self-managed-queue-topics-acl checkpoints with the exact course generation, source, account, registry and cluster. Each PVC/PV UID/spec/claim/CSI identity and EBS incarnation/tags is rechecked. Relevant Kafka CRs must also match the owner's recorded resource rows. Plan and verify additionally authenticate the current bundle's exact owner manifest/action bytes and CAS control. Unknown or unselected data remains blocked.

This is provisional planning evidence only. Basic core apply requires the earlier owner's authenticated completion receipt and fresh exact Kubernetes/EBS absence. The core snapshot records which provisional identities need that transition. No global DATA_KINDS bypass or name/tag-only cleanup is introduced.

Additional offline suites:

- `python -m unittest discover -s ci -p test_velero_lifecycle.py -v`
- `python -m unittest discover -s ci -p test_lifecycle_data_handoff.py -v`

Version-specific reference for TTL semantics: https://github.com/vmware-tanzu/velero/blob/v1.18.2/pkg/controller/backup_controller.go (prepareBackupRequest). The runtime-role retention test is an offline age/scope model; no live one-week recovery run is claimed.
