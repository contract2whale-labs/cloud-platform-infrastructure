# T8 bounded node drain and recovery

Implemented source adapter, not a deployment result. No live AWS/Kubernetes mutations were used to validate this module. The original lesson is `course/전체교안/쉬운버전/BU16/09-BU16-T8-node-failure.md`, STEP 4 and STEP 5. The original `kubectl drain --ignore-daemonsets --delete-emptydir-data --timeout=180s` is deliberately represented as an exact per-Pod Eviction loop: invoking `kubectl drain` after inventory review could include newly arrived, unapproved Pods.

## Dispatcher wiring

1. Import `from drain_ops import IDS as DRAIN_IDS` and append `DRAIN_IDS` to `OPERATION_IDS`.
2. `snapshot`: for operation in `DRAIN_IDS`, call `drain_ops.snapshot(fixture_io(), operation, r, c, marker)`.
3. `run` apply dispatch: for operation in `DRAIN_IDS`, call `drain_ops.apply(fixture_io(), operation, current, r, mark)`.
4. `recovery_authorized`: only `node-drain-restore` may resume an unresolved marker whose operation is in `DRAIN_IDS`; retain existing owner/environment/account/source/state validation.
5. Add both fixed IDs to workflow choices. The existing configuration guard makes these Dev-only. Both use `incident-dev-mutate`, a read-only plan role, reviewed identical private action/manifest, then protected approval and apply. Do not enable the currently unregistered runtime merely because tests pass.

## Reviewed request contract

Register `environments.dev.node-drain-cycle` in `requests.json`. Common fields remain `source_sha`, `expires_at`, `change_request`, `data_decision`. The decision must explicitly cover each evicted Pod, each disposable emptyDir volume, and original cordon restoration after success or failure. No secrets belong in this request.

Additional fields:

- `node`: exactly `{name, uid, provider_id}` for one original Ready Dev app Node. Fixed labels: `workload=app`, `eks.amazonaws.com/nodegroup=contract2whale-dev-eks-app`.
- `peer_node`: exactly `{name, uid, provider_id}` for a distinct original app Node. It must remain Ready and schedulable before each eviction. It is never mutated. Actual spare CPU/memory, workload health and SLI thresholds must be reviewed separately; Ready alone does not establish spare capacity or healthy business requests.
- `timeout_seconds`: integer 1–180, never a string or bool. No new cordon/eviction after the monotonic deadline. Each Kubernetes request has a five-second transport bound; observation and finally recovery can extend elapsed wall time beyond the drain budget. Hard runner loss can prevent finally; durable recovery marker remains.
- `restore_original_cordon`: boolean true, explicit authorization for automatic restoration.
- `pods`: complete Node inventory across all namespaces. Each entry has `name`, `namespace`, `uid`, `spec_sha256`, `metadata_sha256`, `disposition`, `disposable_emptydir`.
- `pdbs`: complete PDB inventory in `contract2whale-demo`. Each entry has `name`, `namespace`, `uid`, `spec_sha256`, `metadata_sha256`.

Use the read-only `identity(obj)` function in `drain_ops.py` to compute each inventory entry from the actual API JSON. `spec_sha256` hashes canonical JSON of spec. `metadata_sha256` hashes labels, annotations and ownerReferences (including absent values as null). This is an integrity fingerprint, not approval by itself. Inspect the underlying full Pod specs, data ownership, volumes and full PDB selectors before approving fingerprints.

For a controller-owned DaemonSet Pod set `disposition=skip-daemonset`, `disposable_emptydir=[]`. For every other Pod, this fixed operation permits only controller-owned ReplicaSet Pods in the demo namespace; set `disposition=evict`. Set `disposable_emptydir` to the exact list of disposable emptyDir volume names, including memory-backed emptyDir. Empty list is valid only when that evicted Pod has none. hostPath, static/mirror Pods, unmanaged Pods, other namespaces and unsupported owners are refused. PVCs are not deleted. Their detach/reattach and application data consistency are not proven by eviction success.

The PDB inventory includes all selectors, empty selectors, matchExpressions and overlapping selectors through spec hashes. Exactly one reviewed PDB must select each evicted Pod. A fresh observedGeneration and positive disruptionsAllowed are required immediately before eviction. The server-side Eviction API still enforces the actual budget at admission. A budget rejection stops the cycle; it does not remove PDBs, bypass eviction or retry indefinitely. A later distinct approved attempt requires fresh inventory. There is no atomic transaction spanning Node, Pod and PDB objects: a concurrent PDB spec writer after the last check is still an operational race, so maintenance review must exclude concurrent PDB changes; the server continues to apply its current PDB policy.

## Recovery

`node-drain-restore` needs the common reviewed request fields and the original active/recovery-required marker; it does not take replacement Node coordinates. It restores the original same-UID Node's `spec.unschedulable` absent/false/true value with UID and resourceVersion JSON Patch tests, then removes only this operation's lock annotation. The temporary `course.openai.com/drain-owner` value binds the request and original node. A replaced node, missing/foreign lock with changed cordon, or conflicting writer blocks recovery and preserves the marker. If the node is already at the exact original state without a lock, recovery is idempotent. The cycle does not uncordon a node that was originally cordoned.

Evictions use `policy/v1` with Pod UID and resourceVersion preconditions. New/unreviewed Pods are never automatically added to the allowed set. Every Pod disappearance must be accounted for; drift aborts. No direct pod delete, force, disable-eviction, node deletion, EC2 stop/start, second-node mutation or PDB editing exists here.

Before each eviction, the durable marker records the attempted Pod UID; confirmed absences are recorded separately. An ambiguous network result is never automatically replayed. The completed drain observation stores a timestamp and remaining/evicted Pod UIDs in that private marker. The return receipt reports evicted Pod UIDs and restored Node UID/original cordon. `application_recovery=NOT_MEASURED` is intentional. Rebalancing, replacement readiness, SLI success, pending events and business requests need actual separate read-only observation. Restoring schedulability does not move existing Pods back. A failed eviction plus successful cordon recovery is still a failed operation, not a successful drain. A killed runner must use a newly approved `node-drain-restore` plan; do not rerun cycle blindly.

## Minimum permissions and installation

Plan: get Node by name, list Pods cluster-wide for that node inventory, list demo PDBs. Apply: the same reads plus patch only the reviewed Node where RBAC resourceNames can constrain it; create demo `pods/eviction` (Kubernetes RBAC cannot constrain create by resourceNames, so keep the role narrowly scoped and the fixed dispatcher immutable). No Pod delete or PDB mutation is needed. The separate node-protection and cleanup modules retain their own permissions. The ownership annotation is a cooperative drift detector, not an authorization boundary against other cluster administrators.

Runtime registration still requires the verified private EKS/relay, pinned toolchain, protected GitHub environments/OIDC, IAM and Kubernetes permissions, private immutable plan/receipt store and shared lifecycle/incident lock. Install with the common GitOps proposal instructions, not a new public runner kubeconfig or manually executed drain.

Offline verification:

`python -m unittest discover -s gitops-ci-proposal/operations/tests -p test_drain_ops.py -v`

21 fake-API tests cover UID replacement, fixed nodegroup, surviving peer, Pod/PDB drift, emptyDir/hostPath preservation, unmanaged Pods, empty/overlapping selectors, stale/exhausted budgets, timeout type/range, exact Eviction preconditions, failure restoration, absent/false/true cordon, runner recovery and foreign lock preservation. These tests do not establish live capacity, live PDB races, IAM authorization or application recovery.
