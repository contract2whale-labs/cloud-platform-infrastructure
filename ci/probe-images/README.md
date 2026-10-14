# BU07 images: real CI setup and generated digest inputs

These are new, explicit prerequisites. The later BU13 operator publication job is not reused or implied to exist at BU07. Nobody runs AWS create/push locally.

## Instructor, once per release

1. In the instructor's infrastructure repository, copy `instructor/main.tf` into `terraform/environments/dev/bootstrap/probe-images-public/`. Register that exact root/key `bootstrap/probe-images-public/terraform.tfstate` as **retained** in ordinary Terraform CI and its read/plan/apply allowlists. Prepare its provider lock through the existing reviewed lock process. Apply via the standard PR + CI saved-plan workflow. The two public ECR repositories are in us-east-1, with account restriction and prevent_destroy.
2. Copy `Dockerfile` and `publish.py` to `ci/probe-images/`, and `publish.yml` to `.github/workflows/bu07-probe-images.yml`. Create the protected `probe-images-instructor` Environment using the course's existing ACCOUNT_ID, STATE_BUCKET and OIDC AWS_ROLE_ARN setup. Require reviewers and main only. Include `instructor/ci-probe-images-instructor.tf` in the initial instructor BU01 identity bootstrap. If BU01 is already complete, its administrator must first authorize this exact additional role in the identity-maintenance path; the restricted existing role cannot create it by itself. Set the returned `probe_instructor_role_arn` as the Environment `AWS_ROLE_ARN` Variable; also set `ACCOUNT_ID`, `STATE_BUCKET`, `AWS_REGION=ap-northeast-2` Variables. It grants exact public repository publishing, conditional-create receipt writes. The separate ordinary plan/apply policies prepare the retained public repositories before publication.
3. Dispatch `bu07-probe-images` with `mode=instructor`. The job resolves the official Python 3.13 Alpine manifest and official Kubernetes registry.k8s.io/pause:3.10 manifest, records their actual digests, builds the Python diagnostic image for linux/amd64 and linux/arm64, and publishes both to the instructor repositories using the source SHA tag. Existing release tags stop the job. It emits actual immutable image references in the Actions Summary and private versioned S3 receipt. No example digest is supplied or accepted.
4. Review the emitted receipt and distribute its JSON as the course release's `instructor-release.json`. The public images intentionally contain only the Dockerfile/runtime, no credentials, repository source, private State or learner data. The learner PR fixes these exact digest references. A changed official tag at the next instructor build is recorded as a new source digest and release, never silently substituted into a learner's retained checkpoint.

## Learner, before BU07 lifecycle use

1. Copy `learner/main.tf` to `terraform/environments/dev/bootstrap/probe-images/`; register root/key `bootstrap/probe-images/terraform.tfstate` as **retained**. Apply through ordinary reviewed Terraform CI. It creates exactly `course-bu07-python` and `course-bu07-pause`, private in Seoul, strict immutable tags, encryption and scan-on-push, with force_delete=false and prevent_destroy. No ECR expiry policy is installed; paused lifecycle images remain available.
2. Copy the same CI publisher files. Place the **actual instructor-generated receipt** at `ci/probe-images/instructor-release.json` through PR. The parser requires exact public repository names and sha256 references; an absent file stops before mirroring. No invented image variable is needed to start this preparation.
3. Reuse `infra-dev-apply`; do not create a learner publication Environment. Install `learner/ci-probe-images.tf` in Dev ci-identity through identity CI before the repository PR. Existing Variables `ACCOUNT_ID`, `AWS_ROLE_ARN`, `STATE_BUCKET`, `AWS_REGION` are used. The exact policy prepares the two retained repositories through ordinary Terraform and permits publication without repository/image deletion. After main review dispatch `mode=learner`. Shared repository concurrency and the lifecycle/incident guards refuse publication while paused. Pinned Skopeo copies all platform manifests AND their blobs and verifies the unchanged digest. The runner Summary contains image references plus private receipt key, VersionId and SHA-256.
4. Copy the emitted `images.probe_image` and `images.pause_image` values into protected lifecycle Environment variables `EKS_PROBE_IMAGE` and `EKS_PAUSE_IMAGE` for the jobs using this adapter (plan, apply, destroy). Pass them through the workflow environment. The adapter refuses missing/tag-only/foreign-account/wrong-repository values, retains the pair in the source checkpoint, includes them in each saved-plan context, and refuses edits while paused.
5. Retain both repositories and their referenced manifests across Down. The EKS node IAM role already uses the course's ECR pull policy. The probe uses own-account private ECR image pulls and separately verifies public ECR DNS/TLS for the NAT path. No diagnostic image requires Kubernetes API tokens or AWS credentials in its Pod.

## Run commands (DevContainer, infrastructure repository)

```bash
# Instructor: publish only after the protected public repository foundation is applied.
gh workflow run bu07-probe-images.yml --ref main -f mode=instructor
```

```bash
# Learner: mirror the instructor-reviewed digest pair into the own-account retained repositories.
gh workflow run bu07-probe-images.yml --ref main -f mode=learner
# Open the latest request and read its immutable image references and private receipt descriptor.
gh run list --workflow bu07-probe-images.yml --limit 5
```

IAM files and repository main.tf belong in DIFFERENT roots. Copy only main.tf into the bootstrap/probe-images root; copy ci-probe-images*.tf into bootstrap/ci-identity. Include the new managed policies in the course IAM attachment-budget/packing check before applying; two additional learner policy attachments are required unless packed.

The Dockerfile has no foreign-CPU RUN instruction: both platform images use the pinned official Python base without QEMU. Platform manifest checks are automatic; actual EKS diagnostic execution is a separate acceptance check. Registry credentials are temporary private files and removed when the publisher exits.

## Exact ownership/permissions

- Learner repositories: `arn:aws:ecr:ap-northeast-2:<configured account>:repository/course-bu07-python` and `.../course-bu07-pause`. Construct account from the existing protected ACCOUNT_ID; do not paste an example account.
- Repository creation belongs to ordinary Terraform CI, not the publisher. Publication role has `DescribeRepositories`, `DescribeImages`, `BatchGetImage`, `GetDownloadUrlForLayer`, `BatchCheckLayerAvailability`, `InitiateLayerUpload`, `UploadLayerPart`, `CompleteLayerUpload`, `PutImage` on those two resources; `GetAuthorizationToken` is the API's required account-level action.
- Instructor equivalent ECR-public permissions are scoped to its two `us-east-1` public repository ARNs returned by Terraform; authorization APIs require their documented broader resource scope. Identity-policy installation still uses the course's separately reviewed CI identity-maintenance path.
- Lifecycle diagnostic role gets read-only exact retained log bucket/prefix access with ExpectedBucketOwner checks, plus EKS access-entry/RBAC for creation/exec/deletion of run-owned diagnostic namespaces. RBAC is explicit: it is not implied by AWS authentication. No blanket workload cleanup role is introduced.

Only local syntax/mock tests have run. Publication, multiarch availability, vulnerability review, IAM and live EKS execution are CI acceptance tests, not completed cloud work.

## Mechanism references

- [Docker imagetools create](https://docs.docker.com/reference/cli/docker/buildx/imagetools/create/): joining manifests is not a cross-registry blob-copy procedure.
- [Skopeo copy](https://github.com/podman-container-tools/skopeo/blob/main/docs/skopeo-copy.1.md): all-platform copying with digest preservation.
- [AWS ECR Public actions/resources](https://docs.aws.amazon.com/service-authorization/latest/reference/list_ecr-public.html): public repository ARN and action scopes.

The instructor copies only the Linux amd64/arm64 pause children, then joins them in the destination registry. Windows layers are not copied. The resulting instructor index digest is recorded independently of the full upstream index. [Upstream pause version constant](https://github.com/kubernetes/kubernetes/blob/v1.31.0/cmd/kubeadm/app/constants/constants.go) documents the selected 3.10 version; registry availability is checked during the actual publishing job.
