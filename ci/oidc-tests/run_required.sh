#!/usr/bin/env bash
# Required GitHub Linux runner gate. Real cloud credentials are never needed.
set -euo pipefail
umask 077
here="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
if [ "$#" -ne 0 ]; then
  echo 'Required runner accepts no skip or test-selection arguments.' >&2
  exit 1
fi
python="$(command -v python3)"
terraform="$(command -v terraform)"
if [ "$(uname -s)" != Linux ] || [ "$(uname -m)" != x86_64 ]; then
  echo 'Required runner needs Linux x86_64 and the pinned Terraform setup action.' >&2
  exit 1
fi
work="$(mktemp -d "${TMPDIR:-/tmp}/oidc-required.XXXXXXXX")"
cleanup() { rm -rf -- "$work"; }
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# Nothing from the host AWS/GitHub OIDC/Python/Terraform configuration is passed
# to pip, terraform, or tests. The temporary home has no shared credentials.
env -i PATH="$PATH" HOME="$work/home" TMPDIR="$work/tmp" LANG=C.UTF-8 \
  OIDC_TESTS="$here" OIDC_WORK="$work" OIDC_PYTHON="$python" \
  OIDC_TEST_TERRAFORM="$terraform" /bin/bash <<'REQUIRED_GATE'
set -euo pipefail
umask 077
mkdir -p "$HOME" "$TMPDIR" "$OIDC_WORK/toolchain"
requirements="$OIDC_TESTS/requirements-test.txt"
if [ ! -f "$requirements" ]; then requirements="$OIDC_TESTS/../requirements-test.txt"; fi
test -f "$requirements"
"$OIDC_PYTHON" -m venv "$OIDC_WORK/venv"
python="$OIDC_WORK/venv/bin/python"
"$python" -m pip --isolated install --disable-pip-version-check --no-deps \
  --index-url https://pypi.org/simple -r "$requirements"
"$python" -m pip --isolated check

cp "$OIDC_TESTS/toolchain/main.tf" "$OIDC_WORK/toolchain/main.tf"
cp "$OIDC_TESTS/toolchain/.terraform.lock.hcl" "$OIDC_WORK/toolchain/.terraform.lock.hcl"
cat > "$OIDC_WORK/terraform.rc" <<'TERRAFORM_RC'
disable_checkpoint = true
provider_installation {
  direct {
    include = ["registry.terraform.io/hashicorp/aws"]
  }
}
TERRAFORM_RC
export TF_CLI_CONFIG_FILE="$OIDC_WORK/terraform.rc"
export TF_IN_AUTOMATION=true CHECKPOINT_DISABLE=1
# Official registry only; the reviewed lock is read-only and never regenerated.
"$OIDC_TEST_TERRAFORM" -chdir="$OIDC_WORK/toolchain" init \
  -backend=false -input=false -no-color -lockfile=readonly
cmp "$OIDC_TESTS/toolchain/.terraform.lock.hcl" "$OIDC_WORK/toolchain/.terraform.lock.hcl"
export OIDC_TEST_PROVIDER="$OIDC_WORK/toolchain/.terraform/providers/registry.terraform.io/hashicorp/aws/6.62.0/linux_amd64/terraform-provider-aws_v6.62.0_x5"
export OIDC_REQUIRE_TERRAFORM=1
"$python" "$OIDC_TESTS/run_required.py"
REQUIRED_GATE
