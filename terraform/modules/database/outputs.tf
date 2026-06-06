output "endpoint" {
  value = aws_db_instance.main.endpoint
}

output "secret_arn" {
  value = aws_db_instance.main.master_user_secret[0].secret_arn
}
