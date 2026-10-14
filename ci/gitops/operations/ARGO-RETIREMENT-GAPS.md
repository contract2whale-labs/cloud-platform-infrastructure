# Implemented reviewed destructive/selective Argo source fences

Ordinary reconcile does not pass --prune or --resource. These six former fences now dispatch the exact protected operations in `argo_reviewed_ops.py`; see `ARGO-REVIEWED-OPERATIONS.md` and `argo-source-fences.json`. The original line numbers and commands below are provenance, not executable instructions or remaining gaps. No live mutation success is claimed.

- cumulative-lifecycle/course/전체교안/쉬운버전/BU15/13-BU15-T10B-second-release-and-canary.md:2193: `argocd app sync commerce-web-prod --grpc-web --prune --revision "$APPROVED_GITOPS_REVISION"`
- cumulative-lifecycle/course/전체교안/쉬운버전/BU15/07-BU15-T6-prod-operations.md:2360: `argocd --kube-context "$PROD_KUBE_CONTEXT" --port-forward --port-forward-namespace argocd app sync platform-backup-probe-prod --revision "$PROBE_END_REVISION" --prune`
- cumulative-lifecycle/course/전체교안/쉬운버전/BU15/06-BU15-T5-prod-msk-tempo.md:3447: `    argocd app sync "$APP" --revision "$APPROVED_GIT_REVISION" --prune`
- cumulative-lifecycle/course/전체교안/쉬운버전/BU15/09-BU15-T8-prod-data.md:5400: `argocd app sync platform-policies --revision "$POLICY_REVISION" --resource :ConfigMap:delivery-env --resource kyverno.io:ClusterPolicy:verify-image-signature --resource kyverno.io:ClusterPolicy:restrict-image-registries --resource kyverno.io:ClusterPolicy:require-image-digest`
- cumulative-lifecycle/course/전체교안/쉬운버전/BU10B/15-BU10B-T7-collector-agent.md:1200: `argocd --server localhost:8080 --plaintext app sync platform-collection-policy-dev --revision "$REMOVAL_GIT_REVISION" --prune`
- cumulative-lifecycle/course/전체교안/쉬운버전/BU10C/04-BU10C-T3-permissions-and-topics.md:1649: `    argocd app sync "$APP" --revision "$APPROVED_GIT_REVISION" --prune`

- Additional inline source: `BU15/05-BU15-T4-prod-observability.md`, section 6.2, formerly requested Prod collection-policy prune. It now dispatches `argo-collection-log-prod-retire`; the Part3 section carries the same fixed request and UID deletion contract.
