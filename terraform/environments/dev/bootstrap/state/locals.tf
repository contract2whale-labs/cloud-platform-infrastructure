# locals.tf — bootstrap/state 루트 모듈 (dev · prod 공통 코드)
# 입력값으로부터 한 번 확정한 이름을 버킷 리소스와 precondition 이 함께 참조합니다.

locals {
  state_bucket_name = var.state_bucket_name # 예: "company-dev-tfstate-111111111111" (이름 규칙이 계산식으로 바뀌어도 수정 지점은 이 한 곳)
}
