# Operational access proposal

Source-only. No IAM, EKS, Kubernetes, GitHub settings, or remote branches were changed.
Registration ARNs alone do not authorize a job: this proposal creates the roles,
managed policies, EKS access entries, admission boundaries, RBAC, and fresh-cluster
bootstrap handoff those jobs actually need.

## Identities and ownership

- `cp-<env>-gitops-bootstrap`: only `gitops-<env>-bootstrap` OIDC Environment.
- `cp-<env>-gitops-apply`: only `gitops-<env>-apply`.
- `cp-<env>-incident-plan`: only `incident-<env>-plan`.
- `cp-<env>-incident-apply`: only `incident-<env>-mutate` or `incident-<env>-destructive`.
- `gha-infra-<env>-lifecycle-destroy`: only `infra-<env>-destroy`; two protected
  Down gates use this identity. Its service/evidence policy assembly is separately
  owned by the central lifecycle proposal.

Trust reuses the BU01 `local.subject_prefix`, including its exact repository custom
subject, `local.provider_arn` and `local.oidc_host`; audience is `sts.amazonaws.com`.
Managed policy names are `cp-<env>-ci-*`. Normal operation roles explicitly deny IAM
and EKS access self-edit. Plan can write its private saved plans, never mutate cloud
resources or workloads. Port-forward is a transport exception, not workload exec.

## Install and activate, in order

1. Populate `examples/dev.json` into a reviewed Dev/Prod registration using exact
   account/region, State keys, buckets/keys, application names, and live-owned cloud
   resources. Example values are not activation values. Render the pinned Argo chart
   privately with the exact bootstrap values; run `register-bootstrap.py` to record
   its cluster object names and archive/render SHA-256. Never commit the private
   render, credentials, tokens or Secret manifests.
2. Compile an immutable bundle:
   `python3 ci/operations-access/access.py --config <reviewed.json> --out ci/operations-access/bundles/<env>`.
   Run `terraform fmt` on the generated `.tf`. Put the bundle's `config_sha256` in
   the GitOps environment registry as `operations_access_config_sha256`.
3. Add the generated `identity/operations.generated.tf` and `operations-policies/`
   **only** to the existing `bootstrap/ci-identity` root. Review/apply with
   identity-admin, preserving existing resource addresses. Include the central
   destroy-role service/evidence attachments to the singular
   `aws_iam_role.operations_lifecycle_destroy`; its generated transport policy
   already consumes one attachment. Do not put EKS or Kubernetes resources here.
4. Merge `terraform/eks-access.tf` into the existing `modules/eks`. Use its existing
   EKS resource and account/environment inputs, not another cluster or State key.
   It creates four `operations` and three `lifecycle` entries and preserves the
   instructor `admin` entry. Duplicate principal membership fails closed. Adjust
   old assertions which required exactly one total entry. CI owns these entries
   and recreates them with each EKS incarnation before application hooks.
5. Copy `workflows/gitops-access-bootstrap.yml` to `.github/workflows/`. Keep its
   shared infrastructure concurrency group. Configure exact protected Environments,
   main-only deployment branches, independent reviewers, non-bypass approvals and
   matching role/account/region variables. The image is an immutable registry digest.
   Package `ci/operations-access.py` with the other canonical CI helpers.
6. After a new EKS/relay exists, dispatch `gitops-access-bootstrap.yml` with environment,
   the reviewed `access-manifest.json` SHA-256 and, when present, the exact private
   course checkpoint version/hash/generation. The dedicated job uses **runner** EKS
   credentials over the private SSM proxy, installs admission/RBAC, then the pinned
   Argo chart/CRDs/Projects. It writes private, versioned, incarnation-bound receipts.
7. Rerun the same cumulative Up command. It resumes the retained checkpoint only
   after verifying the bootstrap receipt; it does not run privileged bootstrap as
   ordinary infra apply. Incident fixture namespace UIDs come from that verified
   receipt, not stale configuration. Enable ordinary workflows only after live
   authorization checks below pass.

## Explicit privileged boundary

`operations_bootstrap` is a **persistent**, Terraform-owned EKS ClusterAdmin policy
association on `cp-<env>-gitops-bootstrap` only. Initial RBAC installation cannot
self-authorize. This role is therefore an explicitly privileged, separately approved
bootstrap boundary, not a claim of namespace-only authority. Its fixed job rejects
an already-started or completed cluster incarnation, uses pinned source/bundle/chart,
and never changes the lifecycle checkpoint. An interrupted marker requires reviewed
recovery; there is no blind retry, marker deletion or alternate identity fallback.
No normal GitOps/incident/infra apply role gets this association. Changing the trusted
workflow remains a privileged code-review action.

Global unknown-kind teardown inventory belongs only to the protected destruction
role (apart from bootstrap's explicit admin capability). Native RBAC cannot make a
Secret `list` permission metadata-only. Ordinary jobs have no Secret inventory grant,
including backup labs; the latter now enumerate only Pod/PVC. See `PERMISSIONS.md`
for unavoidable IAM/RBAC parameter granularity and source mappings.

## Verification

`python3 -m unittest discover -s ci/operations-access/tests -v` passes 26 tests.
Python compilation, workflow YAML parsing and Terraform formatting pass. Local
provider-schema validation was attempted but blocked by the executor's provider
UNIX-socket restriction; it is **not** reported as passed. No live policy simulator,
OIDC session, admission dry-run, Kubernetes authorization or private relay was tested.

Before activation, run Terraform validate/mock plan with the course's pinned AWS
provider, review IAM Access Analyzer findings, and run negative/positive
`kubectl auth can-i` checks using each real role through the private session. Ordinary
roles must fail global Secret listing, IAM/access edits, kube-system mutation and
namespace deletion; incident-plan must fail pod exec and workload mutation. Test
server-side dry-run admission against an unregistered Application/cluster-role name,
verify the exact EKS group mapping, and confirm private S3 versions/KMS encryption.
Finally test a fresh-cluster bootstrap → same-checkpoint Up → ordinary scoped job.

## Existing Dev AWS-operation bridge (T14)

After the original `aws-fixed-operations.tf` identities exist, install the generated
`optional-aws-fixed/aws-fixed-bridge.generated.tf` in that same identity root with
its `operations-policies/aws-fixed-bridge.json`. It attaches transport/versioned
State-read permission to the existing `gha-aws-ops-dev-plan/apply` roles, without
blocking their separately reviewed exact writer IAM-policy operation. Then review
`aws_fixed_operations_enabled=true` in the EKS root; default false avoids creating
access entries for identities not yet available at BU06. The two `aws_fixed` entries
have only `cp:dev:aws-fixed-plan/apply` groups; apply can operate fixed trace Pods in
`observability`, plan can only read. There is no EKS admin association for these roles.
This setting is retained/replayed with the EKS root on later Up.

The private bootstrap receipt also records exact live installer residual
Namespace/RBAC/admission rows (UID, full non-metadata spec digest and metadata policy
digest). Destruction must authenticate this proof and compare unchanged live rows;
installer names alone are never an unknown-resource exception.
