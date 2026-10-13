# main.tf — network/vpc 루트 모듈 (dev · prod 공통 코드)
# 환경은 명시적 입력과 backend key 로 구분하고 CLI workspace 는 default 만 씁니다.
# terraform_data 는 Terraform 내장 리소스라 AWS API 를 호출하지 않습니다.

resource "terraform_data" "workspace_guard" {
  input = terraform.workspace # 예: "default" (선택한 workspace 를 State 에 기록; 조건은 plan 때 평가)

  lifecycle {
    precondition {
      condition     = terraform.workspace == "default" # 예: "default" 통과 / "drill" 거부
      error_message = "Use the default workspace; select each environment with explicit variables and a distinct backend key."
    }
  }
}
