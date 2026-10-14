output "associated_secret_arns" { value = aws_msk_scram_secret_association.queue_user.secret_arn_list }
