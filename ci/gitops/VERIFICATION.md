# Offline verification and activation boundary

Verified locally on 2026-10-13; no cloud mutation or live CI success is claimed.

- GitOps/core unit tests: 49 passed.
- Fixed operational unit tests: 145 passed.
- Application lifecycle unit tests: 20 passed.
- All 69 workflow operation choices exactly match the fixed dispatcher registry.
- Python source compiles.
- Both original and Part3 course copies route the implemented operations through trusted-main CI. Local trace queries use existing-Service GET transport; synthetic sends use fixed CI actions.

The supplied operations.json remains disabled until the instructor publishes the locked toolchain/chart artifacts and registers actual account, State, source, image, OIDC, access-bundle and protected Environment bindings. Follow PUBLISH-AND-ACTIVATE.md and the operations-access installer. Disabled registration is not an implementation stub, and it is not evidence that a learner's cluster is ready.

Both lifecycle wrappers authenticate bootstrap proof against the fresh EKS incarnation. Up additionally binds the retained generation and source checkpoint. The reviewed action manifest pins the private proof's S3 VersionId and content SHA. Initial Up start is metadata-only, so the cluster can be recreated before the protected bootstrap handoff. Ordinary mutation paths cannot bypass that handoff.

Core Down uses the protected destroy inspector. Installer Namespace/RBAC/admission/default-SA/default-ConfigMap residuals are admitted only through authenticated exact live UID/spec/metadata rows. General incident and GitOps roles do not require global Secret inventory. Data-bearing or unknown resources remain fail-closed.

The builder incident includes its own synthetic trace under one saved action and marker: zero replicas, fixed one-span POST, exact-ID blocks query, finally restore replicas, same-ID requery, exact Pod UID cleanup. Unknown creation outcomes cannot be adopted, and deletion retries require durable UID-specific deletion intent. The receipt reports observations separately from replica restoration.
