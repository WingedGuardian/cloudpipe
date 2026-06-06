output "alb_dns" {
  value = aws_lb.main.dns_name
}

output "app_sg_id" {
  value = aws_security_group.app.id
}

output "log_group_arn" {
  value = aws_cloudwatch_log_group.app.arn
}
