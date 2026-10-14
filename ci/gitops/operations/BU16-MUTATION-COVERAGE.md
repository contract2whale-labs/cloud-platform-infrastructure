# BU16 mutation routing and evidence

All handlers below are implemented as fixed trusted-main plan/review/apply operations. Unit tests are offline; no cloud execution has been claimed. Local read-only diagnostics remain optional.

| Source | Executable CI operation |
|---|---|
| T1 replicas / T12 builder | selfheal-demo / builder-cycle, builder-restore |
| T2 query Pod cleanup | query-pod-cleanup |
| T3–T6 unavailable instructor preparation files | newly authored fixture-t3/t4/t5/t6-cycle, -restore, -cleanup; see instructor-only documents |
| T7 during/after connectivity Job | db-connect-during, db-connect-after, db-connect-cleanup |
| T8 drain / diagnostic PDB cleanup | node-drain-cycle, node-drain-restore, t8-pdb-cleanup |
| T8A demand / namespace / PriorityClass | demand-scale bounded cycle, demand-restore, t8a-cleanup |
| T8A original Node protection annotation | node-protection-cycle captures baseline; node-protection-restore consumes marker |
| T8A nodegroup limit/restore | aws-operations-proposal fixed AWS adapter |
| T11/T14 exact deny policy removal | aws-operations-proposal fixed AWS adapter |
| T13 producer ACL experiment | producer-acl-cycle/recover: bounded credential issuance, one-tuple denial, baseline restore and seven-day cleanup |
| T15 diagnostic Job / probe CM cleanup | pool-diagnostic, job-cleanup, probe-configmap-cleanup |
| T16 source/restored/after read Jobs | pitr-read-source, pitr-read-restored, pitr-read-after |
| T16 one synthetic product row transaction | pitr-fix-row, explicit reviewed data decision |
| T16 Jobs / restored DB cleanup | job-cleanup receipt → later AWS clone-delete adapter |
| T18A exact approved ECR image digests | ecr-cleanup; repository deletion unsupported |

## Explicit installation and source boundaries

The newly authored T3–T6 fixtures replace absent instructor artifacts; they do not claim to recover those missing historical files. Old objects with missing baseline provenance are not adopted. The node-protection recovery similarly requires a baseline captured by the fixed cycle; unknown historical annotations remain protected. Any original preparation shell that creates production-impacting faults must be replaced by an individually reviewed fixed handler or the isolated fixture route, never passed as dispatcher input.

Operations registration and requests remain learner configuration until exact account, protected roles, versioned State, binary/image/chart digests, source revisions, EKS image pull access and request approvals are supplied. This is runnable implementation code with fail-closed activation, not evidence that those bindings or a live cluster already exist. Exact mutation replacements in the course text must point to these CI operations; labeling old mutation commands “CI” without replacing them is insufficient.
