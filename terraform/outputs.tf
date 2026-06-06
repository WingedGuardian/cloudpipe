output "alb_dns" {
  value = module.compute.alb_dns
}

output "task_role_arn" {
  value = module.iam.task_role_arn
}

output "ci_plan_role_arn" {
  value = module.iam.ci_plan_role_arn
}

output "ci_apply_role_arn" {
  value = module.iam.ci_apply_role_arn
}
