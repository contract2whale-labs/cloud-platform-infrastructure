# Source and verification

Inspected the provided tooling copy under `assets/infrastructure/bootstrap/argocd/` (no Git metadata accompanies this extracted copy). Source SHA256:

- bootstrap.py: d7d1a3c404602897b3a394a884517fad361e84035c3c4e54b00ad9a37d12f045
- values.yaml: b0340b0ccfd4acf942f5cb7071d5c9b96166ce83df3e2e0d910d1b49a6fd8bc4
- github-known-hosts: c73ac5d045cd2a359d2202b79b551fb22a638463d5ddbe5ed59b1b3998869c88

Course cross-checks: BU06 private API session (SSM to Squid 3128), BU08 cert-manager install (namespace before controller; full sync; immutable Git revision and per-source receipt), BU08B mesh install (base → CNI → istiod → ztunnel → policy). Original chart versions remain provenance, not an assertion of immutable registry artifacts. New bootstrap code is a bounded adaptation, not byte-for-byte execution of the original script.

2026-10-13 local verification:

- 36 unittest cases passed, including mocked full reconcile command order (get/manifests/diff/sync/wait/get), no prune/selective sync, revision receipts, mutable source/image rejection, scoped app/project checks, ownership collision checks and disabled registration before subprocess.
- Python compilation passed.
- Workflow YAML parsed; trusted-main trigger and OIDC job permission checks passed.
- Disabled activation rejected as intended before AWS credentials.
- No live AWS/GitHub/Kubernetes/Argo operation was executed. GitHub Environment enforcement, EKS/SSM network reachability, Helm chart values compatibility and Argo account authentication are release acceptance tests, not passed tests.

Added executable core/mesh/gateway lifecycle start/plan/verify/apply hooks, versioned private action plans, independent CAS checkpoints, UID-bound foreground retirement, LB controller ordering, and checkpoint restore. Hook tests cover replacement/finalizer/data rejection, controller ordering, resume, expired/swapped manifests and changed State bindings. Exact residual receipt integration with the central engine/EKS guard is a release requirement. Arbitrary prune/forced finalizer deletion, data-bearing Kubernetes retirement, entire admission/network mutation suites and mTLS negative experiments remain outside this adapter. Optional local read-only diagnostics are allowed.
