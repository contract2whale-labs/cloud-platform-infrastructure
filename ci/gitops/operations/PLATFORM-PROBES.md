# Fixed platform probes (BU08B–BU15)

These handlers extend the existing saved-plan protected workflow, not the normal
GitOps reconcile path. Requests are reviewed JSON in `operations/requests.json`;
copy only the intended operation from the expired example registrations and fill
actual values. The workflow has no manifest, script, SQL, namespace, or URL input.
Prod uses the existing protected incident-prod-mutate/destructive gates; a button
press alone does not approve an action.

## Inputs and sources

`platform_probe_image`, `database_operator_image`, and `trace_probe_image` are
instructor-published immutable image references in environment registration. No
mutable tags or example digest is accepted as publication evidence. Source files
are fetched by exact reviewed Git SHA and canonical-compared to the fixed course
assets under templates/platform. Command, SQL, identity, namespace, service account,
network shape, and policy changes require a reviewed handler/template change.

- mesh-probes-create/cleanup: the actual four course Deployments, exact per-probe
  service accounts and selectors, shared experiment UUID, source-derived images.
- collection-probe-create/cleanup: actual collection-boundary-client Deployment.
  The course defines no diagnostic Job here; do not mislabel it as one.
- seed-readback-create/cleanup: actual Dev/Prod read-only SQL Jobs. Only product
  count and publishable key query; never arbitrary SQL. Secret values and Job logs
  never enter Actions output or public receipts. Inspect sensitive output only in
  the protected diagnostic session; the workflow receipt reports completion only.
- trace-probe-create/cleanup: one Pod sends one fixed synthetic span to exactly
  the e2 distributor or collection gateway. Typed trace/span IDs and timestamp;
  immutable curl image; HTTP 200 and zero rejected spans verified. Later live/block
  query observations remain separate evidence, never inferred from send success.
- application-strict-cycle/restore: temporary namespace STRICT PeerAuthentication,
  exact four app/root identities and complete policy baseline, bounded 30–600 s
  observation, UID/RV-preconditioned automatic restoration. Explicit restore is
  only for the nonexpiring original recovery marker; it is not a second normal step.
- grafana-secret-refresh: one UID/RV-conditional force-sync annotation on the exact
  GitOps-owned grafana-admin ExternalSecret, no secret value read.
- notification-probe-create/cleanup: actual PrometheusRule (historical source path
  happens to be operations/jobs), fixed alert/expression, at most 600 s expiry.
  Alert delivery remains independently verified; creation alone is not delivery.
- velero-lab-backup/restore/cleanup: exact existing GitOps backup-probe writer/data
  and pre-created shared namespaces. Writes one approved synthetic UUID file;
  captures UID/PVC/PV, creates the exact source Backup, requires one successful EBS
  snapshot, creates the exact source Restore into empty backup-probe-restored,
  verifies new volume snapshot/size/AZ and file hash. Cleanup deletes only restored
  writer/data using original UID+resourceVersion, then verifies PV/EBS disappearance.
  Namespace, Backup/Restore CRs and snapshots are retained; no namespace deletion.

## Recovery and ownership

Creation is always create, never apply/upsert. Existing names are not adopted.
Private creation receipts are S3 key/version/hash-bound to the same account,
environment, operation and repository. Cleanup reviews current child-owner closure
and rejects changed specs, labels, owners, namespace or UID. Partial failures leave
nonexpiring recovery markers. An unknown creation response cannot authorize a
name-only delete. Do not widen a marker or fabricate a receipt to bypass this stop.

The original deploy-probes/trace helper examples explain source behavior; learner
execution now dispatches the fixed handler instead of running their mutation paths.
Immutable source-derived payloads, not arbitrary runtime script inputs, are used.
All original and Part3 mutation fences point to the same concrete workflow.

## Verification

`python3 -m unittest discover -s gitops-ci-proposal/operations/tests`

Tests are mocked/static. They do not claim any AWS, Kubernetes, delivery, backup,
restore or notification operation actually ran.
