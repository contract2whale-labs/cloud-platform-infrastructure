#!/usr/bin/env bash
# DevContainer에서 최초 준비 또는 의존성 변경 때 실행합니다.
set -euo pipefail
repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo"
# 기존 backend 캐시를 건드리지 않는 작업공간 임시 디렉터리입니다.
cache="$(mktemp -d "$repo/.terraform-module-locks.XXXXXX")"
trap 'rm -rf -- "$cache"' EXIT
for p in modules/*; do
  if [ ! -d "$p/tests" ]; then continue; fi
  if ! compgen -G "$p/*.tf" > /dev/null && ! compgen -G "$p/*.tf.json" > /dev/null; then
    continue
  fi
  echo "== $p"
  export TF_DATA_DIR="$cache/${p##*/}"
  # 기존 lock을 존중하며 자동 upgrade는 하지 않습니다.
  terraform -chdir="$p" init -backend=false -input=false
  terraform -chdir="$p" providers lock -platform=linux_amd64 -platform=linux_arm64
done
echo '모듈별 .terraform.lock.hcl의 git diff를 검토한 뒤 소스와 함께 커밋하세요.'
