locals {
  name = "vulntracker-api"
  tags = {
    app         = local.name
    environment = var.environment
    managed-by  = "terraform"
    data-class  = "confidential"
  }
  service_account = "vulntracker-api"
}
