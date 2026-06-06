module "cloudpipe" {
  source = "../../"

  environment     = "dev"
  github_org      = var.github_org
  container_image = var.container_image
}
