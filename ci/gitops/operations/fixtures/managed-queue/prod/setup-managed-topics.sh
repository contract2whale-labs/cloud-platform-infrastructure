#!/usr/bin/env bash
# platform/environments/dev/queue/scripts/setup-managed-topics.sh
# 관리형 큐(MSK)에 업무 토픽을 만들고 ACL 을 겁니다.
# 자체 구축 큐의 선언(gitops/platform/kafka/overlays/dev 의 KafkaTopic · KafkaUser)과 같은 값을 명령으로 옮긴 것입니다.
# 관리자 자격은 이 실행 전용입니다. 종료 후 연결 해제하고 7일 회수 가능한 삭제를 예약합니다; 즉시 영구 부재를 주장하지 않습니다.
#   임시 Secret 생성 -> MSK 에 연결 -> queue-admin Pod 에 설정 전달 -> 토픽·ACL -> 대조 -> 임시 토픽 왕복 -> 연결 해제·Secret 삭제
# 여러 번 실행해도 결과가 같습니다 (--if-not-exists, ACL add 는 멱등).
# 사용: 보호된 CI가 승인된 source/State/Pod UID와 fixed request를 검증한 뒤 아래 변수를 주입합니다. 로컬 직접 실행 금지.
#   KUBE_CONTEXT, EXPECTED_ACCOUNT_ID, AWS_REGION, MANAGED_QUEUE_REQUEST_ID(승인 요청 ID), MANAGED_QUEUE_APPROVED_CLUSTER_ARN(승인한 MSK ARN)
set -euo pipefail
set +x # 비밀번호·SecretString·Pod 설정은 Actions 로그에 노출하지 않습니다.
[ "${GITHUB_ACTIONS:-}" = true ] || { echo "protected platform-credential-operations CI only" >&2; exit 2; }
: "${MANAGED_QUEUE_RUN_ID:?승인한 고정 UUID}" "${CI_MANAGED_QUEUE_APPROVAL_SHA:?exact private plan hash}" "${APPROVED_QUEUE_ADMIN_UID:?승인 Pod UID}"
[[ "$CI_MANAGED_QUEUE_APPROVAL_SHA" =~ ^[0-9a-f]{64}$ ]] || exit 2
[[ "$MANAGED_QUEUE_RUN_ID" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]] || exit 2
# 이 env 표식만으로 승인으로 취급하지 않습니다. CI wrapper가 source/State/Pod/plan/gate를 검증하고 주입합니다.
cd "$(dirname "$0")/.."
: "${KUBE_CONTEXT:?}" "${EXPECTED_ACCOUNT_ID:?}" "${AWS_REGION:?}" "${MANAGED_QUEUE_REQUEST_ID:?}" "${MANAGED_QUEUE_APPROVED_CLUSTER_ARN:?}"
RELEASE=platform-tempo-e2
WRITER=tempo-distributor
READER=tempo-consumer
ADMIN=queue-admin

# 큐 계약(비밀 아닌 output)을 읽고, 승인한 클러스터와 같은지 확인합니다.
QUEUE=$(python3 ../../../../automation/read_platform_contract.py --component queue --environment "${ENVIRONMENT:-dev}" --expect-account "$EXPECTED_ACCOUNT_ID")
CLUSTER_ARN=$(jq -r '.cluster_arn' <<< "$QUEUE")
CLUSTER_NAME=$(jq -r '.cluster_name' <<< "$QUEUE")
BOOTSTRAP=$(jq -r '.bootstrap_brokers_scram' <<< "$QUEUE")
KMS_KEY=$(jq -r '.kms_key_arn' <<< "$QUEUE")
TOPIC=$(jq -r '.topic_name' <<< "$QUEUE")
PARTITIONS=$(jq -r '.partitions' <<< "$QUEUE")
[ "$CLUSTER_ARN" = "$MANAGED_QUEUE_APPROVED_CLUSTER_ARN" ] || { echo "승인한 클러스터와 계약의 클러스터가 다릅니다" >&2; exit 1; }

RUN_ID="$MANAGED_QUEUE_RUN_ID" # private action plan에서 승인한 실제 UUID
SMOKE=smoke-$RUN_ID
SECRET_NAME=AmazonMSK_${CLUSTER_NAME}_${ADMIN}_$RUN_ID
CONFIG=/tmp/queue-admin-$RUN_ID.properties
K="kubectl --context $KUBE_CONTEXT -n monitoring"
check_pod_uid() {
  [ "$($K get pod queue-admin -o jsonpath='{.metadata.uid}')" = "$APPROVED_QUEUE_ADMIN_UID" ] || { echo "queue-admin Pod replaced; stop" >&2; return 2; }
}
kt()  { check_pod_uid && $K exec -i queue-admin -- bin/kafka-topics.sh --bootstrap-server "$BOOTSTRAP" --command-config "$CONFIG" "$@"; }
acl() { check_pod_uid && $K exec -i queue-admin -- bin/kafka-acls.sh --bootstrap-server "$BOOTSTRAP" --command-config "$CONFIG" "$@" > /dev/null; }
mkdir -p local-inputs

SECRET_ARN=""
diff=0
cleanup() {
  rc=$?
  trap - EXIT
  cleanup_ok=true
  check_pod_uid || cleanup_ok=false
  if [ "$cleanup_ok" = true ]; then
    kt --delete --if-exists --topic "$SMOKE" >/dev/null 2>&1 || cleanup_ok=false
    $K exec queue-admin -- rm -f -- "$CONFIG" || cleanup_ok=false
  fi
  if [ -n "$SECRET_ARN" ]; then
    response=$(aws kafka batch-disassociate-scram-secret --region "$AWS_REGION" --cluster-arn "$CLUSTER_ARN" --secret-arn-list "$SECRET_ARN" --output json) || cleanup_ok=false
    jq -e '.UnprocessedScramSecrets == []' <<< "${response:-{}}" >/dev/null || cleanup_ok=false
    associated=$(aws kafka list-scram-secrets --region "$AWS_REGION" --cluster-arn "$CLUSTER_ARN" --output json) || cleanup_ok=false
    jq -e --arg arn "$SECRET_ARN" '(.NextToken == null) and (.SecretArnList | index($arn) == null)' <<< "${associated:-{}}" >/dev/null || cleanup_ok=false
    if [ "$cleanup_ok" = true ]; then
      deleted=$(aws secretsmanager delete-secret --region "$AWS_REGION" --secret-id "$SECRET_ARN" --recovery-window-in-days 7 --output json) || cleanup_ok=false
      jq -e --arg arn "$SECRET_ARN" '.ARN == $arn and .DeletionDate != null' <<< "${deleted:-{}}" >/dev/null || cleanup_ok=false
      metadata=$(aws secretsmanager describe-secret --region "$AWS_REGION" --secret-id "$SECRET_ARN" --output json) || cleanup_ok=false
      jq -e --arg arn "$SECRET_ARN" '.ARN == $arn and .DeletedDate != null' <<< "${metadata:-{}}" >/dev/null || cleanup_ok=false
    fi
  fi
  jq -n --arg run "$RUN_ID" --arg request "$MANAGED_QUEUE_REQUEST_ID" --arg secret "$SECRET_ARN" --arg uid "$APPROVED_QUEUE_ADMIN_UID" --argjson cleanup "$cleanup_ok" \
    '{run_id:$run,request_id:$request,temporary_secret_arn:$secret,queue_admin_uid:$uid,cleanup_verified:$cleanup,secret_deletion:"scheduled-recoverable-7-days"}' > "local-inputs/managed-credentials-$RUN_ID.json"
  [ "$rc" = 0 ] && [ "$diff" = 0 ] && [ "$cleanup_ok" = true ] || { echo "FAIL request=$MANAGED_QUEUE_REQUEST_ID run=$RUN_ID; preserve private receipt; no blind retry" >&2; exit 1; }
  echo "PASS request=$MANAGED_QUEUE_REQUEST_ID run=$RUN_ID (임시 자격 연결 해제·7일 회수 가능 삭제 예약 확인; 영구 부재 아님)"
}
trap cleanup EXIT

# 1. 이번 실행 전용 관리자 Secret 을 새로 만들어 MSK 에 연결합니다 (비밀번호는 stdin 으로만 전달).
PASSWORD=$(python3 -c 'import secrets; print(secrets.token_urlsafe(36))')
SECRET_ARN=$(jq -n --arg u "$ADMIN" --arg p "$PASSWORD" '{username: $u, password: $p}' \
  | aws secretsmanager create-secret --region "$AWS_REGION" --name "$SECRET_NAME" --kms-key-id "$KMS_KEY" \
      --secret-string file:///dev/stdin --tags "Key=platform-queue-run,Value=$RUN_ID" "Key=platform-queue-request,Value=$MANAGED_QUEUE_REQUEST_ID" \
      --query ARN --output text)
aws kafka batch-associate-scram-secret --region "$AWS_REGION" --cluster-arn "$CLUSTER_ARN" --secret-arn-list "$SECRET_ARN" > /dev/null

# 2. queue-admin Pod 에 클라이언트 설정을 넣고, MSK 의 주기적 동기화로 인증이 통할 때까지 기다립니다 (최대 5분).
umask 077
check_pod_uid
cat <<EOP | $K exec -i queue-admin -- sh -c "umask 077; cat > $CONFIG"
security.protocol=SASL_SSL
sasl.mechanism=SCRAM-SHA-512
sasl.jaas.config=org.apache.kafka.common.security.scram.ScramLoginModule required username="$ADMIN" password="$PASSWORD";
EOP
unset PASSWORD
for _ in $(seq 30); do kt --list > /dev/null 2>&1 && break; sleep 10; done
kt --list > /dev/null

# 3. 관리자 ACL 을 먼저 남겨야, 뒤에 제한 규칙을 적용한 뒤에도 ACL 을 계속 관리할 수 있습니다.
acl --add --allow-principal "User:$ADMIN" --operation All --cluster
acl --add --allow-principal "User:$ADMIN" --operation All --topic '*'
acl --add --allow-principal "User:$ADMIN" --operation All --group '*'

# 4. 토픽 (값은 gitops/platform/kafka/overlays/dev/topic.yaml 과 같습니다)
kt --create --if-not-exists --topic "$TOPIC" --partitions "$PARTITIONS" --replication-factor 3 \
  --config min.insync.replicas=2 --config retention.ms=43200000 --config retention.bytes=-1 --config segment.bytes=268435456 \
  --config cleanup.policy=delete --config compression.type=producer --config max.message.bytes=16000000 > /dev/null

# 5. ACL (gitops/platform/kafka/overlays/dev/kafkauser-tempo-*.yaml 의 규칙을 같은 순서로 옮긴 것)
acl --add --allow-principal "User:$WRITER" --operation Write --operation Describe --topic "$TOPIC"
acl --add --deny-principal  "User:$WRITER" --operation Create --topic '*'
acl --add --deny-principal  "User:$WRITER" --operation Create --cluster
acl --add --allow-principal "User:$READER" --operation Read --operation Describe --topic "$TOPIC"
for group in block-builder metrics-generator; do
  acl --add --allow-principal "User:$READER" --operation Read --operation Describe --group "$group"
done
for zone in a b c; do
  acl --add --allow-principal "User:$READER" --operation Read --operation Describe --group "$RELEASE-live-store-zone-$zone" --resource-pattern-type prefixed
done
acl --add --deny-principal "User:$READER" --operation Write --operation Create --operation Delete --topic '*'
acl --add --deny-principal "User:$READER" --operation Create --cluster

# 6. 만든 결과를 대조합니다: 토픽 설정, ACL 의 대상·동작·그룹 패턴
DESC=$(kt --describe --topic "$TOPIC")
for want in "PartitionCount: $PARTITIONS" "ReplicationFactor: 3" "min.insync.replicas=2" "retention.ms=43200000" "retention.bytes=-1" \
            "segment.bytes=268435456" "cleanup.policy=delete" "compression.type=producer" "max.message.bytes=16000000"; do
  if grep -qF -- "$want" <<< "$DESC"; then echo "OK    $want"; else echo "DIFF  $want"; diff=1; fi
done
ACLS=$($K exec queue-admin -- bin/kafka-acls.sh --bootstrap-server "$BOOTSTRAP" --command-config "$CONFIG" --list)
python3 scripts/verify-managed-acls.py --topic "$TOPIC" --writer "$WRITER" --reader "$READER" --release "$RELEASE" <<< "$ACLS" || diff=1
{ echo "$DESC"; echo "$ACLS"; } > "local-inputs/managed-topics-$RUN_ID.txt"   # 비밀 없는 조회 결과만 보관

# 7. 격리 왕복: 임시 토픽에 3건을 쓰고 읽어 TLS·SASL 경로가 통하는지만 봅니다 (업무 토픽에는 쓰지 않음)
kt --create --topic "$SMOKE" --partitions 1 --replication-factor 3 --config min.insync.replicas=2 > /dev/null
echo -e "one\ntwo\nthree" | $K exec -i queue-admin -- bin/kafka-console-producer.sh --bootstrap-server "$BOOTSTRAP" --producer.config "$CONFIG" --topic "$SMOKE" > /dev/null
consumed=$($K exec queue-admin -- bin/kafka-console-consumer.sh --bootstrap-server "$BOOTSTRAP" --consumer.config "$CONFIG" --topic "$SMOKE" --group "$SMOKE" --from-beginning --max-messages 3 --timeout-ms 60000 2> /dev/null | grep -c .)
if [ "$consumed" = 3 ]; then echo "OK    smoke 왕복 3건"; else echo "DIFF  smoke 왕복 $consumed건 (3건이어야 함)"; diff=1; fi
