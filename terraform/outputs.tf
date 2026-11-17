output "iam_role_arn" {
  description = "IRSA role assumed by the API pod."
  value       = aws_iam_role.api.arn
}

output "jwt_secret_arn" {
  description = "Populate out-of-band: aws secretsmanager put-secret-value --secret-id <arn> --secret-string \"$(openssl rand -base64 48)\""
  value       = aws_secretsmanager_secret.jwt_signing_key.arn
}

output "notify_api_key_secret_arn" {
  value = aws_secretsmanager_secret.notify_api_key.arn
}

output "public_url" {
  value = "https://${var.public_hostname}"
}
