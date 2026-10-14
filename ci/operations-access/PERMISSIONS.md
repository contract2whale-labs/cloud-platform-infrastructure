# Source-to-permission boundaries

The compiler is executable policy/RBAC source, not a claim that registered ARNs
already exist. All names/ARN inputs are reviewed before identity-admin applies it.

## AWS

- `gitops_ops.own`, `private-api-session.py`: exact EKS cluster Describe; regional
  EC2 instance/SSM status reads; SSM port forwarding only. StartSession targets are
  restricted to the same account/region and four existing Terraform relay tags
  (`Name=cp-<env>-private-api-relay`, Environment, Component, ManagedBy). The actual
  instance ID comes from fresh versioned State. This deliberately survives relay
  replacement without granting shell/SendCommand or instance-role assumption.
  Retagging is unavailable to ordinary operation roles. Session data-channel access
  is limited to the caller's `${aws:userid}` session prefix.
- `Store`, lifecycle/incident markers: bucket safety inspection; exact State-key and
  marker prefix listings; versioned reads; separate incident-plan writes and apply
  receipts/CAS marker writes; no evidence or State deletes. GitOps writes only its
  private receipt prefix. KMS access requires S3 service and exact key/bucket context.
  Reading Terraform State necessarily reads the entire authorized State object;
  IAM cannot select only non-secret outputs.
- Incident read: exact registered ECR repositories, RDS databases/snapshots,
  Secrets Manager **metadata**, Lambda image functions, EKS PodIdentity association;
  regional EC2 volumes/snapshots/endpoints and consumer-list calls. List/Describe
  actions lacking resource-level scope use `*` with an exact requested region.
- Incident apply: Dev ECR BatchDeleteImage; Prod exact DB ModifyDBInstance; Dev exact
  S3 Gateway endpoint ModifyVpcEndpoint. These APIs cannot restrict IAM to only
  image digests, deletion-protection, or endpoint-policy fields respectively; the
  fixed source/hash/UID-bound reviewed handler supplies those limits. There is no
  RDS deletion, EBS deletion, S3 data deletion, endpoint deletion or IAM mutation.
- Managed queue: exact MSK ARN, only `AmazonMSK_<cluster>_queue-admin_*` temporary
  Secrets, request tags, exact KMS key, recoverable deletion of at least seven days.
  T13 recovery alone may read a temporary Secret version whose VersionId equals
  its `platform-queue-run` resource tag; other/application Secret values and bulk
  Secret reads remain explicitly denied. Passwords never enter plans/logs/receipts.
  These are powerful credential/topic operations and stay behind the protected
  mutate gate. Existing MSK service-role/KMS grants must already be Terraform-owned.

## Kubernetes

- Ordinary GitOps: exact `argocd` namespace, reviewed Application names, server
  service/pod reads and port-forward; no workload/Secret/RBAC writes. A native
  admission policy supplies the exact-name boundary for Application CREATE,
  which RBAC `resourceNames` cannot constrain.
- Bootstrap: chart namespace objects, CRDs, cluster roles/bindings and AppProjects
  have concrete RBAC source; native admission constrains chart/access cluster
  object names. Its separately documented EKS admin association still makes this
  an explicitly privileged initial-install identity; these RBAC declarations do
  not narrow an additive EKS ClusterAdmin association.
- Incident read: explicit consumer/workload kinds for ECR, drain and policy closure;
  reads within registered Argo, demo, monitoring, observability and probe namespaces.
  Incident apply: exact replica/Node patches, demo Jobs/ConfigMaps and Pod eviction,
  namespace/kind-scoped probes, named writer/queue-admin exec, Velero Backup/Restore,
  exact restored Pod/PVC deletion and exact obsolete PriorityClass cleanup.
  Fixed T3–T6 namespaces are precreated/restricted; per-object cleanup retains RBAC.
  Neither role may delete a Namespace or edit RBAC. Plan has port-forward but no exec.
- Dynamic Job/Pod CREATE and prefix-shaped names cannot be narrowed with native
  RBAC resourceNames. Namespace/kind grants are broader than the fixed handler's
  runtime name/UID/spec checks; immutable reviewed workflow code is part of the
  authorization boundary. Do not describe those grants as arbitrary-command-safe.
- Destruction role: global `get/list/watch` is intentionally powerful, including
  Secret objects, for unknown-resource closure. Keep raw inventory in private
  memory/evidence and emit only digests/metadata. Normal lifecycle Up roles get
  scoped Argo restoration and system readiness only, never global inventory.

## References

- [Kubernetes RBAC name/create limitations](https://kubernetes.io/docs/reference/access-authn-authz/rbac/)
- [EKS additive access policy and RBAC authorization](https://docs.aws.amazon.com/eks/latest/APIReference/API_CreateAccessEntry.html)
- [EKS IAM resource types](https://docs.aws.amazon.com/service-authorization/latest/reference/list_eks.html)
- [SSM session policy examples](https://docs.aws.amazon.com/systems-manager/latest/userguide/getting-started-restrict-access-quickstart.html)
- [Secrets Manager condition keys](https://docs.aws.amazon.com/service-authorization/latest/reference/list_secretsmanager.html)
- [MSK action resource types](https://docs.aws.amazon.com/service-authorization/latest/reference/list_kafka.html)

BU07/Up network diagnostics use precreated `course-node-probes`, not disposable
namespaces. Only lifecycle-apply can create the two probe Pods, exec `probe-net`,
or UID-delete those named Pods. It cannot delete the namespace. Native admission
requires the run label, own-account digest-pinned `course-bu07-{pause,python}`
images, no service-account token, no host namespaces/volumes/init containers, and
restricted PodSecurity. The bootstrap receipt records this namespace's UID.
