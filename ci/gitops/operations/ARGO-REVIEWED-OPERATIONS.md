# Reviewed Argo source operations

These seven operations close the six exact selective/retirement fences plus the Prod collection inline procedure recorded in `ARGO-RETIREMENT-GAPS.md`. They use `argo_reviewed_ops.py` through the existing saved-action incident CI dispatcher. This is implementation and fixture-test evidence, not a report of successful AWS/Kubernetes execution.

## Fixed operations

| Operation | Environment | Scope |
| --- | --- | --- |
| `argo-collection-log-retire` | Dev | `platform-collection-policy-dev`: only `team-platform-check/agent-log-check` Pod |
| `argo-collection-log-prod-retire` | Prod | `platform-collection-policy-prod`: only `team-platform-check/agent-log-check` Pod |
| `argo-queue-admin-dev-retire` | Dev | `platform-queue-admin-dev`: only `monitoring/queue-admin` Pod and NetworkPolicy |
| `argo-queue-admin-prod-retire` | Prod | Same exact resources under `platform-queue-admin-prod` |
| `argo-backup-probe-retire` | Prod | `platform-backup-probe-prod`: exact original synthetic `backup-probe/writer` Pod, `data` PVC and verification of its CSI volume deletion |
| `argo-commerce-config-retire` | Prod | `commerce-web-prod`: one approved old `contract2whale-demo/commerce-web-config-<10-character hash>` ConfigMap |
| `argo-platform-policies-selective` | Prod | `platform-policies`: `argocd/delivery-env` ConfigMap and `verify-image-signature`, `restrict-image-registries`, `require-image-digest` ClusterPolicies |

No request chooses an arbitrary App, namespace, resource kind, source path, API verb, shell command, selector or manifest. Queue retirement never removes MSK, Secrets, the reader/writer workloads or general network policies. No operation deletes an Application, Namespace, Backup, Restore or snapshot.

## Request and installation contract

Register the exact source leaf in `operations.json.applications`, and its retained parent chain in `authority_applications` / `authority_children`. The existing source app-of-apps owns every leaf. All declared Git sources use full reviewed SHAs; automated sync stays off. At the four-policy-only stage, register `deferred_applications: ["platform-policies"]`: the normal root still owns/registers this leaf and render/diff is reviewed, but ordinary reconcile skips full leaf sync and reports the deferral. The selective operation requires this field. Remove it only through a later reviewed activation PR after the remaining policy resources are ready. Existing rendered child declarations must exactly match registration. The incident plan/apply workflow must supply protected `ARGOCD_AUTH_TOKEN` with App read/render/diff permissions, plus the existing pinned `argocd` tool and private EKS access. Deletion uses Kubernetes `DeleteOptions`, not `argocd --prune` or a deletion-approved annotation. Selective sync uses the Application operation API with CAS tests and four fixed resources only.

All operations require normal common request fields (`source_sha`, timezone-aware `expires_at`, `change_request`, `data_decision`), plus:

- `application_uid`: actual approved leaf Application UID
- `request_id`: new UUID for this action; retain it for recovery of the same action
- `target_uids`: exact map of `GROUP/Kind/namespace/name` to observed UID. Core group is empty, so its keys start with `/`. Selective creation uses an explicitly approved JSON `null` only when that exact object is absent. No other missing object is adopted.
- Commerce adds `old_configmap_name` with the exact Kustomize hash name.
- Backup adds `experiment_id` for the exact original synthetic UUID and the private versioned successful Velero restore `creation_receipt` and the exact synthetic-proof requirements documented by the Velero adapter. The storage proof is mandatory, not an optional force switch.

Exact `data_decision` values:

- Collection: `delete-exact-agent-log-check-pod`
- Queue: `delete-exact-queue-admin-pod-and-networkpolicy`
- Backup: `delete-exact-original-disposable-probe-pod-pvc-and-volume`
- Commerce: `delete-exact-unreferenced-old-commerce-configmap`
- Policies: `sync-only-delivery-env-and-three-image-policies`

Example collection map: `{"/Pod/team-platform-check/agent-log-check":"<observed UID>"}`. Queue includes `/Pod/monitoring/queue-admin` and `networking.k8s.io/NetworkPolicy/monitoring/queue-admin`. Backup includes `/Pod/backup-probe/writer` and `/PersistentVolumeClaim/backup-probe/data`. Policy keys are `/ConfigMap/argocd/delivery-env` and `kyverno.io/ClusterPolicy//<fixed policy name>`.

Requests are reviewed on main, then workflow dispatch supplies only the environment and finite operation ID. The workflow plans read-only, saves the action, rendered desired manifests, exact private diff, UID inventories and authority fingerprints into private S3; protected approval applies those same version/hash-bound bytes after fresh identity/State checks. All retirements belong to destructive approval Environments; policies use the protected mutation Environment. Registration examples are intentionally not populated with fictional production UIDs.

## Retirement gates

Before any deletion:

1. Check the leaf and its entire retained root chain against registered source specs and live UIDs, exact tracking ownership, completed immutable revisions and disabled automated reconciliation.
2. Render the exact approved leaf Git revision through Argo and capture its full private diff. Reject hooks, mutable workload images, unsafe force/replace options, duplicate resources and foreign Argo authorities.
3. Read the full Argo comparison resource inventory and exact approved-revision diff, then list only the fixed target resource kinds in their fixed namespaces. Every reported stale resource and every live tracked object in those bounded lists absent from desired must belong to the exact retirement set; additional candidates, a missing Argo inventory, comparison errors or a wrong comparison revision fail closed. There is no cluster-wide API discovery or Secret listing. Queue and backup desired sets must be empty. Other resources remain untouched even when their diff is nonempty.
4. Match the exact approved target UID and tracking identity. Keep namespace identities fixed. Never delete a controller-owned child by guessing its name.
5. For commerce, retain a declared replacement hashed ConfigMap and reject references from all current Pods, including init containers, projected volumes and terminating Pods. Old ReplicaSet history is retained.
6. For the original backup PVC, bind the successful synthetic backup/restore receipt, original and restored UID/PV/EBS binding, expected content hash and finite Pod/PVC inventory during plan. In approved apply, fixed commands verify the exact synthetic file hash, ordinary file type, no extra files, and empty lost+found before any write or delete. Plan roles never have pods/exec. Deletion of the original requires its explicit data decision and storage reclaim policy. Keep the restore, snapshot, Backup and restored data retained.
7. Record durable deletion intent before each API call. Delete the specific URI with both UID and current resourceVersion preconditions. Observe actual absence, never interpret an API error as absence and never remove finalizers. Recheck the retained App chain before and after mutation.

The source's broad `--prune` intent is reduced to its explicitly approved fixed objects, eliminating blanket Argo prune's same-name replacement race. Retirements report CI UID deletion receipts; a previous Argo operation `Succeeded` is not claimed as proof of this deletion.

## Four-resource selective operation

The full approved rendered desired/diff is private review evidence, but the operation contains exactly the four fixed `GROUP:KIND:NAME` resources and their namespaces, `prune=false`, and the approved revision. It checks selected live UIDs immediately before submitting the Application operation using leaf UID/resourceVersion/spec JSON-patch tests. This Argo API does not provide per-child UID atomicity for an apply: the protected execution role and exclusive review window must exclude concurrent writers of those four objects. The controller's selective apply is not a UID-precondition delete. An unowned or replaced child before submission is rejected; no whole-App fallback, hook execution, automatic sync or application-wide health claim is allowed.

A unique token links the submitted operation to the saved request. Completion requires that token, exact approved revision, successful results for exactly four resources, live desired-field and tracking verification, and an unchanged root chain. SecretStores, ExternalSecrets, Rollouts RBAC and unrelated App resources are deliberately outside the selected operation.

## Partial failure and recovery

All mutation writes durable `active` / `recovery-required` / `idle` markers. Deletion failures retain the original UID set, completed keys and the exact pending-delete intent. A fresh protected plan may continue the same operation, request UUID, source SHA and original full UID map. An absent object is accepted only when the original marker proves its deletion was attempted or already completed. Replacements are never adopted or deleted. The current desired/source/authority/namespace set is reviewed again.

Selective sync records its token and intent before patching. An interrupted/ambiguous submission is recovered by observing that exact original operation; it is never blindly resubmitted. If the recorded operation cannot be proven, the marker remains unresolved for explicit investigation. No path clears another operation's marker.

## Source and tests

`argo-source-fences.json` records the six original/Part3 fence pairs and the additional Prod collection procedure. Both versions dispatch the same fixed IDs; queue helper `up` reads the main reconcile result and `down` requests the fixed protected retirement workflow. The actual Prod helper invocations were also replaced. No user-side direct prune/selected sync survives these exact six fences or the additional Prod collection procedure.

Run `python -m unittest discover -s ci/gitops/operations/tests -p test_argo_reviewed_ops.py -v`. Tests use fake Kubernetes/Argo data and temporary files only; no live mutation is performed.

The fixed Velero Backup source explicitly includes only Pod/PVC/PV kinds in backup-probe. It cannot export Secrets, unrelated CRs or general namespace content. The restore receipt must match repository, account, region, environment and the exact synthetic UUID. Original PVC retirement requires Delete reclaim policy, separate verified retained restored storage, unchanged Backup/Restore identities and an available completed snapshot. Original PV/EBS absence is observed through Kubernetes/AWS reads only; no direct AWS deletion is issued.
