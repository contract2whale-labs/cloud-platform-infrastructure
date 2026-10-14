# Fixed BU16 AWS drill CI

Executable, unactivated proposal. Nothing here has run against AWS/GitHub.

The source-backed operation set is closed:
- rds-pitr-create: an isolated private PostgreSQL PITR clone from the exact live source ARN/DbiResourceId, current restorable window and current subnet/SG/parameter/class settings. Uses actual T16 flags and Environment/Purpose/IncidentRun tags.
- rds-clone-delete: exact clone from its authenticated original creation receipt, never the main Terraform DB. Requires exact Kubernetes diagnostic-job UID cleanup receipt. Preserves automated backups and requires a unique final snapshot and retained encryption key; the old lesson's skip-final-snapshot/delete-backups shortcut is deliberately unavailable.
- scram-admin-disassociate: exact temporary externally issued admin Secret ARN from the approved MSK cluster; checks the complete unprocessed array and subsequent complete association list.
- scram-admin-schedule-delete: only 7–30 day recoverable deletion, after association absence. Exact original admin issuance receipt, ARN/name/KMS/tags and source State exclusion are required. Retained writer/reader Secret containers cannot be selected. No force deletion or secret-value read is implemented.

The temporary admin issuer is external in the supplied source. `temporary_admin_issuance_receipt` is therefore an integration requirement, not a claimed existing publisher. Its private versioned evidence must identify this incident UUID, account and original ARN/name. If it is missing, plan stops. This code does not generate credentials or claim permission to do so.

## Installation

Copy bu16-aws-drill.yml to .github/workflows. Requests are reviewed, committed `incidents/requests/<UUID>.json` documents, not arbitrary CLI input. The request operation and explicit operation_authorization must agree, with an expiry and disposable-drill/retention decisions. validate_request() defines the complete allowed field schema. No credentials or arbitrary command fields are accepted.

Publish/register the existing pinned GitOps operator image first. Select refuses an unactivated registry or mutable tag. Configure separate `incident-dev-aws-plan` and `incident-dev-aws-mutate` environments with account/region/State bucket/role variables. Mutation environment must have real Required reviewers, no administrator bypass and only main deployment permission; the code checks this before planning/execution. Shared Terraform concurrency and active course status prevent overlap with cumulative Down/Up.

Identity-admin must install narrowly scoped role permissions: reads for the exact source/retained State keys; versioned private plans/logs; own nonexpiring incident recovery marker; RDS Describe/ListTags and exact approved source/clone/snapshot creation/deletion resources; MSK exact-cluster association reads/disassociate; SecretsManager Describe/Delete on the explicit temporary admin ARN only. Do not grant wildcard delete on retained secrets, S3 or KMS. Existing roles/permissions are not assumed installed.

Plan stores immutable JSON action parameters, request digest, source State fingerprints and observed service identities in private versioned S3. Apply downloads that exact version/hash, freshly repeats identity/state/TTL checks and executes only the fixed command in the approved plan. It writes a persistent requesting marker before the mutation and an accepted receipt before polling.

Success is confirmed separately: available clone with identical ARN/DbiResourceId; absent clone plus available encrypted final snapshot; disassociated admin ARN; or scheduled recoverable Secret deletion. Scheduling is not permanent absence. An uncertain API response or timeout leaves the marker blocked and forbids automatic replay. `observe` can read an accepted pending request without repeating the mutation; manual protected reconciliation is still required to clear an old recovery marker after that read-only observation. A request that failed before an accepted identity receipt requires explicit investigation rather than adopting a same-name resource.

Receipt paths: ci-logs/<repo>/<run>/<attempt>/<sha>/dev/incident/<operation>/apply/receipt.json, with key/version/sha256 descriptor. Creation receipt includes context, original request, result.DBInstance ARN/DbiResourceId, verified availability/endpoint observations, plan descriptor and STS session. Coordinate log retention so the receipt remains available until clone cleanup; missing receipt blocks deletion.

Kubernetes Job cleanup uses the other worker's incident-completion receipt: exact account/repository, successful job-cleanup operation, reviewed cleanup request hash and complete original Job UID set. The RDS adapter never executes arbitrary Kubernetes YAML or deletes Jobs.

Five offline operation/observation tests and four fully mocked saved-action pipeline tests pass (exact action, read-only verify, tamper rejection, uncertain-request replay block). Provider/IAM permissions, gate configuration, cross-worker receipt integration and actual cloud behavior still require integration tests before activation.
