# ---------------------------------------------------------------------------
# Secrets live in AWS Secrets Manager, encrypted with a customer-managed key.
# Terraform creates the *containers* only; values are set out-of-band
# (aws secretsmanager put-secret-value / rotation Lambda) so they never land in
# Terraform state, plan output, CI logs, manifests or env vars.
# ---------------------------------------------------------------------------

data "aws_caller_identity" "current" {}

resource "aws_kms_key" "secrets" {
  description             = "CMK for VulnTracker application secrets"
  enable_key_rotation     = true
  deletion_window_in_days = 30

  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [
      {
        Sid       = "AccountAdmin"
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root" }
        Action    = "kms:*"
        Resource  = "*"
      }
    ]
  })
}

resource "aws_kms_alias" "secrets" {
  name          = "alias/${local.name}-${var.environment}"
  target_key_id = aws_kms_key.secrets.key_id
}

resource "aws_secretsmanager_secret" "jwt_signing_key" {
  name                    = "${var.environment}/${local.name}/jwt-signing-key"
  description             = "HS256 signing key for VulnTracker access tokens (>= 32 random bytes)"
  kms_key_id              = aws_kms_key.secrets.arn
  recovery_window_in_days = 30
}

resource "aws_secretsmanager_secret" "notify_api_key" {
  name                    = "${var.environment}/${local.name}/notify-api-key"
  description             = "Bearer key the API presents to the notification service"
  kms_key_id              = aws_kms_key.secrets.arn
  recovery_window_in_days = 30
}

# ---- IRSA: only this service account may read only these two secrets --------

data "aws_iam_policy_document" "assume" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    principals {
      type        = "Federated"
      identifiers = [var.oidc_provider_arn]
    }
    condition {
      test     = "StringEquals"
      variable = "${var.oidc_provider_url}:sub"
      values   = ["system:serviceaccount:${var.namespace}:${local.service_account}"]
    }
    condition {
      test     = "StringEquals"
      variable = "${var.oidc_provider_url}:aud"
      values   = ["sts.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "api" {
  name               = "${local.name}-${var.environment}"
  assume_role_policy = data.aws_iam_policy_document.assume.json
}

data "aws_iam_policy_document" "read_secrets" {
  statement {
    sid       = "ReadOwnSecrets"
    actions   = ["secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret"]
    resources = [aws_secretsmanager_secret.jwt_signing_key.arn, aws_secretsmanager_secret.notify_api_key.arn]
  }
  statement {
    sid       = "DecryptViaSecretsManagerOnly"
    actions   = ["kms:Decrypt"]
    resources = [aws_kms_key.secrets.arn]
    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["secretsmanager.${var.aws_region}.amazonaws.com"]
    }
  }
}

resource "aws_iam_role_policy" "read_secrets" {
  name   = "read-app-secrets"
  role   = aws_iam_role.api.id
  policy = data.aws_iam_policy_document.read_secrets.json
}
