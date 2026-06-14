variable "github_org" { type = string }

variable "container_image" {
  type    = string
  default = "cloudpipe-app:latest"
}
