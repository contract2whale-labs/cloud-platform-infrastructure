#!/usr/bin/env bash
# ci/tf-run.sh — workflow 들이 함께 쓰는 작은 도우미입니다. (필요: bash, jq, git, terraform, aws)
#
# root 고르기 (결과는 JSON 배열 한 줄)
#   pick-up <챕터>                 챕터까지 만들 Dev root, 적용 순서
#   pick-down <챕터>               챕터까지 지울 Dev root, 삭제 순서(적용 순서의 역순)
#   pick-changed <이전sha> <새sha>  그 사이에 바뀐 Dev root(공통 module 이 바뀌면 모든 Dev root), 적용 순서
# terraform 실행 (root 하나씩)
#   check-account                  로그인한 AWS 계정이 기대한 계정인지 확인
#   plan <root> [destroy]          init 후 plan 을 저장하고 변경 요약을 남김
#   summary-sha <root>             마지막 plan 의 변경 요약 해시
#   apply <root> [기대요약해시]    저장한 plan 적용(해시를 주면 같은지 먼저 확인)
#   empty <root>                   root 의 state 에 resource 가 남지 않았는지 확인
#
# 실행 환경 변수: STATE_BUCKET AWS_REGION EXPECTED_ACCOUNT_ID TF_VARS_JSON(선택) REPO_PRIVATE(true 이면 plan 원문 표시)
set -euo pipefail

REGISTRY="${REGISTRY:-ci/roots.json}"
SUMMARY_PATTERN='^(Plan:|No changes\.|Changes to Outputs:)|^  # .* (will be|must be) '

# ---------- 공통 ----------
# 디렉터리가 실제로 있는 등록 root 경로 목록(JSON 배열)
existing_paths() {
  local p
  for p in $(jq -r '.roots[].path' "$REGISTRY"); do
    if [ -d "$p" ]; then echo "$p"; fi
  done | jq -R . | jq -sc .
}

# 등록된 root(또는 CI 신원 root)만 다룹니다.
need_root() {
  local root="$1"
  if ! jq -e --arg p "$root" 'any(.roots[]; .path == $p)' "$REGISTRY" > /dev/null \
    && ! [[ "$root" =~ ^terraform/environments/(dev|prod)/bootstrap/ci-identity$ ]]; then
    echo "등록되지 않은 root 입니다: $root" >&2
    exit 1
  fi
  if [ ! -d "$root" ]; then
    echo "디렉터리가 없습니다: $root" >&2
    exit 1
  fi
}

state_key() { echo "$1" | sed -E 's#^terraform/environments/[^/]+/##'; }

# ---------- root 고르기 ----------
pick_up() {
  jq -c --arg ch "$1" --argjson ex "$(existing_paths)" '
    .chapter_order as $o
    | ($o | index($ch)) as $n
    | if $n == null then error("알 수 없는 챕터: " + $ch)
      else [ .roots[] | . as $r
             | select($r.env == "dev" and $r.chapter != null
                      and (($o | index($r.chapter)) // 99) <= $n
                      and ($ex | index($r.path)) != null) ]
      end' "$REGISTRY"
}

pick_down() {
  jq -c --arg ch "$1" --argjson ex "$(existing_paths)" '
    .chapter_order as $o
    | ($o | index($ch)) as $n
    | if $n == null then error("알 수 없는 챕터: " + $ch)
      else [ .roots[] | . as $r
             | select($r.env == "dev" and $r.chapter != null and $r.down == true
                      and (($o | index($r.chapter)) // 99) <= $n
                      and ($ex | index($r.path)) != null) ] | reverse
      end' "$REGISTRY"
}

pick_changed() {
  local before="$1" after="$2" files
  if [[ "$before" =~ ^0+$ ]] || ! git cat-file -e "${before}^{commit}" 2> /dev/null; then
    echo "비교할 이전 commit 을 찾지 못해 자동 선택을 건너뜁니다. Up 을 직접 실행합니다." >&2
    echo '[]'
    return 0
  fi
  files="$(git -c core.quotepath=false diff --name-only "$before" "$after")"
  # 공통 module(terraform/modules 또는 최상위 modules)이 바뀌면 PR plan 과 같은 범위, 즉 존재하는 모든 Dev root 를 고릅니다.
  jq -c --arg files "$files" --argjson ex "$(existing_paths)" '
    ($files | split("\n")) as $f
    | ($f | any(startswith("terraform/modules/") or startswith("modules/"))) as $mod
    | [ .roots[] | . as $r
        | select($r.env == "dev" and $r.chapter != null
                 and ($ex | index($r.path)) != null
                 and ($mod or ($f | any(startswith($r.path + "/"))))) ]' "$REGISTRY"
}

# ---------- terraform ----------
check_account() {
  if [ "$(aws sts get-caller-identity --query Account --output text)" != "$EXPECTED_ACCOUNT_ID" ]; then
    echo "로그인한 AWS 계정이 기대한 계정과 다릅니다." >&2
    exit 1
  fi
}

tf_init() {
  local root="$1" key vars
  key="$(state_key "$root")"
  vars="${TF_VARS_JSON:-}"
  if [ -z "$vars" ]; then vars='{}'; fi
  (
    cd "$root"
    # TF_VARS_JSON 에서 이 root 의 입력만 꺼내 terraform.tfvars.json 으로 만듭니다.
    echo "$vars" | jq --arg k "$key" '.[$k] // {}' > terraform.tfvars.json
    {
      echo "bucket              = \"$STATE_BUCKET\""
      echo "key                 = \"$key/terraform.tfstate\""
      echo "region              = \"$AWS_REGION\""
      echo "encrypt             = true"
      echo "use_lockfile        = true"
      echo "allowed_account_ids = [\"$EXPECTED_ACCOUNT_ID\"]"
    } > backend.hcl
    terraform init -input=false -lockfile=readonly -backend-config=backend.hcl
  )
}

tf_plan() {
  local root="$1" mode="${2:-}" destroy="" title
  need_root "$root"
  if [ "$mode" = destroy ]; then destroy=1; fi
  tf_init "$root"
  (
    cd "$root"
    if [ "${REPO_PRIVATE:-false}" = true ]; then
      terraform plan -input=false -lock-timeout=5m ${destroy:+-destroy} -out=change.tfplan
    else
      # public 저장소: plan 의 값이 공개 로그에 남지 않도록 출력을 파일로만 받습니다.
      rc=0
      terraform plan -input=false -no-color -lock-timeout=5m ${destroy:+-destroy} -out=change.tfplan > plan.stdout.txt 2>&1 || rc=$?
      if [ "$rc" -ne 0 ]; then
        echo "terraform plan 실패 (종료 코드 $rc). public 저장소라 오류 제목만 표시합니다."
        grep -E -A3 'Error:' plan.stdout.txt | head -n 40 || true
        exit "$rc"
      fi
    fi
    terraform show -no-color change.tfplan > plan.txt
    # 변경 대상과 개수만 모은 요약입니다. 승인한 내용과 같은지 확인할 때 이 요약의 해시를 씁니다.
    grep -E "$SUMMARY_PATTERN" plan.txt > plan.summary.txt || true
    sha256sum plan.summary.txt | cut -d' ' -f1 > plan.summary.sha256
    if [ "${REPO_PRIVATE:-false}" != true ]; then cat plan.summary.txt; fi
    if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
      title="terraform plan${destroy:+ (삭제)}"
      {
        if [ "${REPO_PRIVATE:-false}" = true ]; then
          echo "### $title: $root"
          echo '~~~text'
          head -c 60000 plan.txt
          echo
          echo '~~~'
        else
          echo "### $title 요약: $root"
          echo "public 저장소라 변경 값은 남기지 않고 변경 대상과 개수만 남깁니다."
          echo '~~~text'
          cat plan.summary.txt
          echo '~~~'
        fi
      } >> "$GITHUB_STEP_SUMMARY"
    fi
  )
}

summary_sha() { cat "$1/plan.summary.sha256"; }

tf_apply() {
  local root="$1" expect="${2:-}"
  need_root "$root"
  if [ -n "$expect" ] && [ "$(summary_sha "$root")" != "$expect" ]; then
    echo "승인한 변경 요약과 다릅니다. apply 를 중단합니다: $root" >&2
    exit 1
  fi
  (
    cd "$root"
    if [ "${REPO_PRIVATE:-false}" = true ]; then
      terraform apply -input=false -lock-timeout=5m change.tfplan
    else
      # public 저장소: 적용 로그에서 resource 값(id 등)은 빼고 진행 상황만 표시합니다.
      rc=0
      terraform apply -input=false -no-color -lock-timeout=5m change.tfplan > apply.log 2>&1 || rc=$?
      sed -E 's/ \[id=[^]]*\]//' apply.log | grep -E '(Creating|Modifying|Destroying|Creation complete|Modifications complete|Destruction complete)|^Apply complete' | head -n 200 || true
      if [ "$rc" -ne 0 ]; then
        echo "terraform apply 실패 (종료 코드 $rc). public 저장소라 오류 제목만 표시합니다."
        grep -E -A3 'Error:' apply.log | sed -E 's/ \[id=[^]]*\]//' | head -n 40 || true
      fi
      exit "$rc"
    fi
  )
}

tf_empty() {
  local root="$1" n
  need_root "$root"
  n="$(cd "$root" && terraform show -json | jq '[.. | objects | select(has("mode") and has("type") and has("address"))] | length')"
  if [ "$n" != 0 ]; then
    echo "삭제 뒤에도 state 에 resource $n 개가 남았습니다: $root" >&2
    exit 1
  fi
  echo "state 가 비었습니다: $root"
}

# ---------- 명령 ----------
cmd="${1:-}"
if [ "$#" -gt 0 ]; then shift; fi
case "$cmd" in
  pick-up) pick_up "$1" ;;
  pick-down) pick_down "$1" ;;
  pick-changed) pick_changed "$1" "$2" ;;
  check-account) check_account ;;
  plan) tf_plan "$@" ;;
  summary-sha) summary_sha "$1" ;;
  apply) tf_apply "$@" ;;
  empty) tf_empty "$1" ;;
  *)
    sed -n '2,15p' "$0" >&2
    exit 2
    ;;
esac
