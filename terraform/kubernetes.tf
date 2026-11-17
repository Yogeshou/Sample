# ---------------------------------------------------------------------------
# Namespace with Pod Security Admission "restricted" enforced: the cluster
# itself rejects privileged / root / host-namespace pods in this namespace.
# ---------------------------------------------------------------------------
resource "kubernetes_namespace_v1" "this" {
  metadata {
    name = var.namespace
    labels = {
      "pod-security.kubernetes.io/enforce"         = "restricted"
      "pod-security.kubernetes.io/enforce-version" = "latest"
      "pod-security.kubernetes.io/audit"           = "restricted"
      "pod-security.kubernetes.io/warn"            = "restricted"
    }
  }
}

resource "kubernetes_service_account_v1" "api" {
  metadata {
    name      = local.service_account
    namespace = kubernetes_namespace_v1.this.metadata[0].name
    annotations = {
      "eks.amazonaws.com/role-arn" = aws_iam_role.api.arn
    }
  }
  # The app never talks to the Kubernetes API.
  automount_service_account_token = false
}

# ---------------------------------------------------------------------------
# Secrets Store CSI driver (AWS provider) mounts the secrets as tmpfs files.
# No Kubernetes Secret object is created (no secretObjects sync), and nothing
# sensitive is placed in env vars - the app reads *_FILE paths.
# Requires the secrets-store-csi-driver + AWS provider add-ons on the cluster.
# ---------------------------------------------------------------------------
resource "kubernetes_manifest" "secret_provider_class" {
  manifest = {
    apiVersion = "secrets-store.csi.x-k8s.io/v1"
    kind       = "SecretProviderClass"
    metadata = {
      name      = "${local.name}-secrets"
      namespace = kubernetes_namespace_v1.this.metadata[0].name
    }
    spec = {
      provider = "aws"
      parameters = {
        objects = yamlencode([
          { objectName = aws_secretsmanager_secret.jwt_signing_key.arn, objectAlias = "jwt_secret_key" },
          { objectName = aws_secretsmanager_secret.notify_api_key.arn, objectAlias = "notify_api_key" },
        ])
      }
    }
  }
}

resource "kubernetes_deployment_v1" "api" {
  # checkov:skip=CKV_K8S_14:False positive - var.image is validated to be repo@sha256:<digest>; checkov cannot resolve variables
  # checkov:skip=CKV_K8S_43:False positive - var.image is validated to be repo@sha256:<digest>; checkov cannot resolve variables
  metadata {
    name      = local.name
    namespace = kubernetes_namespace_v1.this.metadata[0].name
    labels    = { app = local.name }
  }

  spec {
    replicas = var.replicas
    strategy {
      # SQLite on a single volume cannot run two writers; switch to RollingUpdate
      # once DATABASE_URL points to a managed database.
      type = "Recreate"
    }
    selector {
      match_labels = { app = local.name }
    }

    template {
      metadata {
        labels = { app = local.name }
      }

      spec {
        service_account_name            = kubernetes_service_account_v1.api.metadata[0].name
        automount_service_account_token = false
        enable_service_links            = false

        security_context {
          run_as_non_root = true
          run_as_user     = 10001
          run_as_group    = 10001
          fs_group        = 10001
          seccomp_profile {
            type = "RuntimeDefault"
          }
        }

        container {
          name              = "api"
          image             = var.image # digest-pinned (validated)
          image_pull_policy = "Always"

          port {
            name           = "http"
            container_port = 8000
            protocol       = "TCP"
          }

          # Non-secret configuration only. Secrets are referenced by *file path*.
          env {
            name  = "APP_ENV"
            value = "production"
          }
          env {
            name  = "JWT_SECRET_KEY_FILE"
            value = "/mnt/secrets/jwt_secret_key"
          }
          env {
            name  = "NOTIFY_API_KEY_FILE"
            value = "/mnt/secrets/notify_api_key"
          }
          env {
            name  = "NOTIFY_SERVICE_URL"
            value = "http://vulntracker-notify.${var.namespace}.svc.cluster.local:3001"
          }
          env {
            name  = "PUBLIC_BASE_URL"
            value = "https://${var.public_hostname}"
          }
          env {
            name  = "CORS_ALLOWED_ORIGINS"
            value = var.cors_allowed_origins
          }

          resources {
            requests = {
              cpu               = "100m"
              memory            = "128Mi"
              ephemeral-storage = "64Mi"
            }
            limits = {
              cpu               = "500m"
              memory            = "256Mi"
              ephemeral-storage = "256Mi"
            }
          }

          security_context {
            allow_privilege_escalation = false
            privileged                 = false
            read_only_root_filesystem  = true
            run_as_non_root            = true
            run_as_user                = 10001
            capabilities {
              drop = ["ALL"]
            }
          }

          liveness_probe {
            http_get {
              path = "/health"
              port = "http"
            }
            initial_delay_seconds = 10
            period_seconds        = 20
          }
          readiness_probe {
            http_get {
              path = "/health"
              port = "http"
            }
            period_seconds = 10
          }

          volume_mount {
            name       = "secrets"
            mount_path = "/mnt/secrets"
            read_only  = true
          }
          volume_mount {
            name       = "data"
            mount_path = "/app/data"
          }
          volume_mount {
            name       = "tmp"
            mount_path = "/tmp"
          }
        }

        volume {
          name = "secrets"
          csi {
            driver    = "secrets-store.csi.k8s.io"
            read_only = true
            volume_attributes = {
              secretProviderClass = kubernetes_manifest.secret_provider_class.manifest.metadata.name
            }
          }
        }
        volume {
          name = "data"
          persistent_volume_claim {
            claim_name = kubernetes_persistent_volume_claim_v1.data.metadata[0].name
          }
        }
        volume {
          name = "tmp"
          empty_dir {
            medium     = "Memory"
            size_limit = "16Mi"
          }
        }
      }
    }
  }
}

resource "kubernetes_persistent_volume_claim_v1" "data" {
  metadata {
    name      = "${local.name}-data"
    namespace = kubernetes_namespace_v1.this.metadata[0].name
  }
  spec {
    access_modes = ["ReadWriteOnce"]
    # Use an encrypted StorageClass (e.g. gp3 with encrypted: "true" + KMS key).
    storage_class_name = "gp3-encrypted"
    resources {
      requests = { storage = "1Gi" }
    }
  }
  wait_until_bound = false
}

resource "kubernetes_service_v1" "api" {
  metadata {
    name      = local.name
    namespace = kubernetes_namespace_v1.this.metadata[0].name
  }
  spec {
    type     = "ClusterIP" # never exposed directly; only through the ingress
    selector = { app = local.name }
    port {
      name        = "http"
      port        = 80
      target_port = "http"
    }
  }
}

resource "kubernetes_pod_disruption_budget_v1" "api" {
  metadata {
    name      = local.name
    namespace = kubernetes_namespace_v1.this.metadata[0].name
  }
  spec {
    max_unavailable = "1"
    selector {
      match_labels = { app = local.name }
    }
  }
}

# ---------------------------------------------------------------------------
# Network policy: default-deny everything in the namespace, then allow only
#   ingress : ingress-controller namespace -> api:8000
#   egress  : api -> cluster DNS, api -> notify:3001
# This also blocks the pod from reaching the cloud metadata endpoint
# (169.254.169.254) and arbitrary internet hosts.
# ---------------------------------------------------------------------------
resource "kubernetes_network_policy_v1" "default_deny" {
  metadata {
    name      = "default-deny-all"
    namespace = kubernetes_namespace_v1.this.metadata[0].name
  }
  spec {
    pod_selector {}
    policy_types = ["Ingress", "Egress"]
  }
}

resource "kubernetes_network_policy_v1" "api" {
  metadata {
    name      = "${local.name}-allow"
    namespace = kubernetes_namespace_v1.this.metadata[0].name
  }
  spec {
    pod_selector {
      match_labels = { app = local.name }
    }
    policy_types = ["Ingress", "Egress"]

    ingress {
      from {
        namespace_selector {
          match_labels = { "kubernetes.io/metadata.name" = var.ingress_controller_namespace }
        }
      }
      ports {
        port     = "8000"
        protocol = "TCP"
      }
    }

    egress {
      to {
        namespace_selector {
          match_labels = { "kubernetes.io/metadata.name" = "kube-system" }
        }
        pod_selector {
          match_labels = { "k8s-app" = "kube-dns" }
        }
      }
      ports {
        port     = "53"
        protocol = "UDP"
      }
      ports {
        port     = "53"
        protocol = "TCP"
      }
    }

    egress {
      to {
        pod_selector {
          match_labels = { app = "vulntracker-notify" }
        }
      }
      ports {
        port     = "3001"
        protocol = "TCP"
      }
    }
  }
}

# ---------------------------------------------------------------------------
# Ingress: TLS only, HSTS, request-size cap and per-IP rate limiting (a
# compensating control for login / share-link brute force).
# ---------------------------------------------------------------------------
resource "kubernetes_ingress_v1" "api" {
  metadata {
    name      = local.name
    namespace = kubernetes_namespace_v1.this.metadata[0].name
    annotations = {
      "cert-manager.io/cluster-issuer"                     = var.cert_manager_cluster_issuer
      "nginx.ingress.kubernetes.io/ssl-redirect"           = "true"
      "nginx.ingress.kubernetes.io/force-ssl-redirect"     = "true"
      "nginx.ingress.kubernetes.io/proxy-body-size"        = "1m"
      "nginx.ingress.kubernetes.io/limit-rps"              = "10"
      "nginx.ingress.kubernetes.io/limit-burst-multiplier" = "3"
      "nginx.ingress.kubernetes.io/limit-connections"      = "20"
    }
  }
  spec {
    ingress_class_name = var.ingress_class_name
    tls {
      hosts       = [var.public_hostname]
      secret_name = "${local.name}-tls"
    }
    rule {
      host = var.public_hostname
      http {
        path {
          path      = "/"
          path_type = "Prefix"
          backend {
            service {
              name = kubernetes_service_v1.api.metadata[0].name
              port {
                name = "http"
              }
            }
          }
        }
      }
    }
  }
}
