variable "aws_region" {
  description = "AWS region hosting the EKS cluster and Secrets Manager."
  type        = string
  default     = "ap-south-1"
}

variable "cluster_name" {
  description = "Existing EKS cluster name."
  type        = string
}

variable "environment" {
  description = "Deployment environment name."
  type        = string
  default     = "prod"
}

variable "namespace" {
  description = "Kubernetes namespace for the API."
  type        = string
  default     = "vulntracker"
}

variable "image" {
  description = "Container image, pinned by digest (repo@sha256:...). Tags are mutable and not accepted."
  type        = string

  validation {
    condition     = can(regex("^[^\\s]+@sha256:[a-f0-9]{64}$", var.image))
    error_message = "image must be pinned by digest, e.g. 123456789012.dkr.ecr.ap-south-1.amazonaws.com/vulntracker-api@sha256:<64 hex>."
  }
}

variable "public_hostname" {
  description = "Public DNS name for the API (used for TLS and share links)."
  type        = string
}

variable "cors_allowed_origins" {
  description = "Browser origins allowed to call the API (comma-separated). Empty disables CORS."
  type        = string
  default     = ""
}

variable "ingress_controller_namespace" {
  description = "Namespace of the ingress controller; the only permitted source of inbound traffic."
  type        = string
  default     = "ingress-nginx"
}

variable "ingress_class_name" {
  type    = string
  default = "nginx"
}

variable "cert_manager_cluster_issuer" {
  description = "cert-manager ClusterIssuer used to obtain the TLS certificate."
  type        = string
  default     = "letsencrypt-prod"
}

variable "oidc_provider_arn" {
  description = "IAM OIDC provider ARN of the EKS cluster (for IRSA)."
  type        = string
}

variable "oidc_provider_url" {
  description = "IAM OIDC provider URL without https:// (e.g. oidc.eks.ap-south-1.amazonaws.com/id/XXXX)."
  type        = string
}

variable "replicas" {
  description = "Replica count. Keep at 1 while the prototype uses SQLite; raise once DATABASE_URL points at a managed database."
  type        = number
  default     = 1
}
