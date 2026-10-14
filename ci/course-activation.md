# Normal CI chapter activation

`ci/roots.json` and `ci/deploy-roots.json` are the complete possible root and dependency catalogs. They do not authorize a deployment. Normal PR preview, push deployment, and requested-root retries select only explicit roots in `ci/course-activation.json`.

```json
{
  "schema": 1,
  "environments": {
    "dev": {
      "prepared_chapter": "BU02",
      "roots": ["terraform/environments/dev/network/vpc"]
    },
    "prod": {"prepared_chapter": null, "roots": []}
  }
}
```

`prepared_chapter` is the source preparation frontier, not a statement that the chapter lab has completed. Root paths remain explicit, so preparing one BU15 step does not activate all other BU15 roots. The lifecycle catalogs assign the earliest allowed chapter; lifecycle Down/Up registration flags, barriers, and hook readiness do not govern ordinary root CI.

## First installation and upgrades

The common installer must receive an explicit `--prepared-chapter`, such as `BU02` or `BU03`, for the first installation. `initial_activation()` generates only the selected environments' cumulative roots from the actual chapter catalog. Its default environment is Dev; Prod preparation must be explicit.

- BU02 Dev: VPC only. The VPC → log-storage catalog edge is deferred for this exact frontier because BU03 introduces the storage split.
- BU03 Dev: VPC and retained network/log-storage. The storage dependency is mandatory from BU03 onward.
- bootstrap/state and bootstrap/ci-identity are external prerequisites and cannot be activated for ordinary CI. State setup and CI identity administration keep their separate ownership.
- Upgrading support tooling preserves the existing activation document. It must not regenerate it using every directory or the newest available chapter.
- The shipped empty document is an inactive template; the installer creates the explicit initial document. Missing activation is an error, never a request to select every directory.

## Prepare authored chapter roots

First author the selected root source, S3 backend, and provider lock. Then preview and save the explicit local change:

```sh
python3 ci/course_activation.py --prepare BU04 --environment dev \
  --roots terraform/environments/dev/account-baseline terraform/environments/dev/account-baseline-dns
python3 ci/course_activation.py --prepare BU04 --environment dev \
  --roots terraform/environments/dev/account-baseline terraform/environments/dev/account-baseline-dns --write
```

These commands make no AWS or GitHub calls. They never add dependencies implicitly. Include every newly needed dependency explicitly, or prepare it in an earlier PR. Review activation and source in the ordinary PR. Source-layout installers use the same pure merge helper for their explicitly selected authored roots; newly introduced provider locks must be generated before submitting that PR.

CI rejects active roots whose checkout is removed, whose direct Terraform source is missing or only example/scaffolding files, whose S3 backend is missing, or whose provider lock is absent/empty. It still checks all Terraform source against the full registry, including inactive future source, to catch unregistered paths.

CI-only and shared-module changes reconcile active roots only. An upstream change selects downstream consumers only when they are already active. Explicit root requests must also name an active root.

## Pure installer API

Import `ci/course_activation.py`; no package dependencies are required:

- `read_catalogs(repo)` returns the Dev/Prod lifecycle chapter catalogs.
- `initial_activation(chapter, catalogs, registry, graph, environments=('dev',))` requires an explicit chapter and returns the initial document.
- `merge_activation(existing, chapter, selected_roots, catalogs, registry, graph)` unions only selected full paths, never removes earlier roots, and advances only their environment's preparation frontier. An empty selected list preserves the existing document exactly.
- `validate_activation(document, registry, graph, catalogs, previous=None)` returns active paths and verifies schema, chapter limits, graph closure, and optional monotonicity.
- `validate_root_readiness(repo, active)` is the filesystem preflight, intentionally separate from pure merge/generation.

Here `registry` is the complete roots JSON object and `graph` is the `dependencies` dictionary from the deploy registry. Additional learner roots must be explicitly registered and activated; generation never discovers or automatically activates them.

PR checks compare against the PR base. Main runs, including manual retries, compare against the last successful deployment, the preceding main commit, and every activation revision in intervening first-parent history. Root removal, activation removal, and backward chapter changes fail closed. Retirement requires a separate reviewed procedure; absence never implies destroy.
