terraform {
  required_version = ">= 1.6.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.73"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.35"
    }
  }

  # Remote, encrypted, locked state. Secret *values* are never written to state
  # because this module creates the secret containers only (see secrets.tf).
  # backend "s3" {
  #   bucket         = "<org>-tfstate"
  #   key            = "vulntracker/api.tfstate"
  #   region         = "ap-south-1"
  #   encrypt        = true
  #   kms_key_id     = "alias/tfstate"
  #   dynamodb_table = "tfstate-lock"
  # }
}

provider "aws" {
  region = var.aws_region
  default_tags {
    tags = local.tags
  }
}

# Authenticates to the EKS cluster with short-lived tokens (no static kubeconfig).
data "aws_eks_cluster" "this" {
  name = var.cluster_name
}

provider "kubernetes" {
  host                   = data.aws_eks_cluster.this.endpoint
  cluster_ca_certificate = base64decode(data.aws_eks_cluster.this.certificate_authority[0].data)
  exec {
    api_version = "client.authentication.k8s.io/v1beta1"
    command     = "aws"
    args        = ["eks", "get-token", "--cluster-name", var.cluster_name]
  }
}
