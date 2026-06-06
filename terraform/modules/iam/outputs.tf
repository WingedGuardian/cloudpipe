output "task_role_arn" {
  value = aws_iam_role.task.arn
}

output "execution_role_arn" {
  value = aws_iam_role.execution.arn
}

output "ci_plan_role_arn" {
  value = aws_iam_role.ci_plan.arn
}

output "ci_apply_role_arn" {
  value = aws_iam_role.ci_apply.arn
}
