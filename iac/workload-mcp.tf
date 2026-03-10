# MCP Server Workload: Cloud Run service with Artifact Registry
#
# Resources:
# - Artifact Registry repository for container images
# - Cloud Run service for MCP server
# - Service account IAM permissions (Secret Manager)
# - IAM binding for unauthenticated access
# - Custom domain mapping with managed SSL

# ============================================
# LOCALS
# ============================================

locals {
  # MCP service configuration from config.yaml
  mcp_name = lookup(local.cloud_run_config, "name", "lastpass-mcp")

  # Artifact Registry configuration
  artifact_registry_config = lookup(local.gcp_resources, "artifact_registry", {})
  artifact_registry_name   = lookup(local.artifact_registry_config, "name", "lastpass-mcp")
  artifact_registry_format = lookup(local.artifact_registry_config, "format", "DOCKER")

  # Docker image (uses Artifact Registry)
  mcp_image = "${local.cloud_run_region}-docker.pkg.dev/${local.project_id}/${google_artifact_registry_repository.mcp.name}/${local.mcp_name}:latest"

  # KMS key resource name for state encryption
  kms_key_name = "projects/${local.project_id}/locations/${local.location}/keyRings/${local.prefix}-${local.location_id}-${local.env}/cryptoKeys/state-encryption"

  # Resource limits from cloud_run config
  mcp_cpu           = lookup(local.cloud_run_config, "cpu", "1")
  mcp_memory        = lookup(local.cloud_run_config, "memory", "256Mi")
  mcp_min_instances = lookup(local.cloud_run_config, "min_instances", 0)
  mcp_max_instances = lookup(local.cloud_run_config, "max_instances", 3)

  # Access configuration
  allow_unauthenticated = lookup(local.cloud_run_config, "allow_unauthenticated", true)

  # Service account email from init module (referenced by name)
  mcp_service_account = "${local.prefix}-cloudrun-${local.env}@${local.project_id}.iam.gserviceaccount.com"

  # OAuth secret name from secrets.tf
  oauth_secret_name = google_secret_manager_secret.oauth_credentials.secret_id

  # Custom domain configuration
  custom_domain = lookup(local.parameters, "domain", "lastpass.mcp.scm-platform.org")
  base_url      = lookup(local.parameters, "base_url", "https://${local.custom_domain}")
  dns_zone      = lookup(local.parameters, "dns_zone", "scm-platform-org")
}

# ============================================
# DATA SOURCES
# ============================================

data "google_project" "current" {
  project_id = local.project_id
}

# ============================================
# ARTIFACT REGISTRY
# ============================================

resource "google_artifact_registry_repository" "mcp" {
  repository_id = local.artifact_registry_name
  location      = local.cloud_run_region
  format        = local.artifact_registry_format
  description   = "Docker repository for LastPass MCP server"

  labels = {
    environment = local.env
    managed_by  = "terraform"
  }
}

# ============================================
# CLOUD RUN SERVICE
# ============================================

resource "google_cloud_run_v2_service" "mcp" {
  name                = local.mcp_name
  location            = local.cloud_run_region
  ingress             = "INGRESS_TRAFFIC_ALL"
  deletion_protection = false

  template {
    service_account = local.mcp_service_account

    scaling {
      min_instance_count = local.mcp_min_instances
      max_instance_count = local.mcp_max_instances
    }

    containers {
      image = local.mcp_image

      resources {
        limits = {
          cpu    = local.mcp_cpu
          memory = local.mcp_memory
        }
        cpu_idle = true
      }

      ports {
        container_port = 8080
      }

      env {
        name  = "HOST"
        value = "0.0.0.0"
      }

      env {
        name  = "SECRET_NAME"
        value = local.oauth_secret_name
      }

      env {
        name  = "BASE_URL"
        value = local.base_url
      }

      env {
        name  = "ENVIRONMENT"
        value = local.env
      }

      env {
        name  = "PROJECT_ID"
        value = local.project_id
      }

      env {
        name  = "FIRESTORE_DATABASE"
        value = google_firestore_database.state.name
      }

      env {
        name  = "KMS_KEY_NAME"
        value = local.kms_key_name
      }
    }
  }

  traffic {
    type    = "TRAFFIC_TARGET_ALLOCATION_TYPE_LATEST"
    percent = 100
  }

  depends_on = [
    google_artifact_registry_repository.mcp,
    docker_registry_image.mcp,
  ]
}

# ============================================
# CUSTOM DOMAIN MAPPING
# ============================================

resource "google_cloud_run_domain_mapping" "mcp" {
  name     = local.custom_domain
  location = local.cloud_run_region

  metadata {
    namespace = local.project_id
  }

  spec {
    route_name = google_cloud_run_v2_service.mcp.name
  }

  depends_on = [google_cloud_run_v2_service.mcp]
}

# ============================================
# DNS RECORD
# ============================================

resource "google_dns_record_set" "mcp" {
  name         = "${local.custom_domain}."
  type         = "CNAME"
  ttl          = 300
  managed_zone = local.dns_zone

  rrdatas = ["ghs.googlehosted.com."]
}

# ============================================
# FIRESTORE DATABASE (session persistence)
# ============================================

resource "google_firestore_database" "state" {
  project                 = local.project_id
  name                    = "${local.prefix}-state-${local.env}"
  location_id             = local.cloud_run_region
  type                    = "FIRESTORE_NATIVE"
  deletion_policy         = "DELETE"
  delete_protection_state = "DELETE_PROTECTION_DISABLED"
}

# ============================================
# SERVICE ACCOUNT PERMISSIONS
# ============================================

resource "google_project_iam_member" "mcp_secretmanager" {
  project = local.project_id
  role    = "roles/secretmanager.secretAccessor"
  member  = "serviceAccount:${local.mcp_service_account}"
}

resource "google_project_iam_member" "mcp_firestore" {
  project = local.project_id
  role    = "roles/datastore.user"
  member  = "serviceAccount:${local.mcp_service_account}"
}

# ============================================
# IAM BINDING FOR PUBLIC ACCESS
# ============================================

resource "google_cloud_run_v2_service_iam_member" "mcp_public" {
  count    = local.allow_unauthenticated ? 1 : 0
  project  = local.project_id
  location = google_cloud_run_v2_service.mcp.location
  name     = google_cloud_run_v2_service.mcp.name
  role     = "roles/run.invoker"
  member   = "allUsers"
}

# ============================================
# OUTPUTS
# ============================================

output "mcp_url" {
  description = "MCP server URL (custom domain)"
  value       = local.base_url
}

output "mcp_cloud_run_url" {
  description = "MCP server Cloud Run URL (direct)"
  value       = google_cloud_run_v2_service.mcp.uri
}

output "mcp_service_account" {
  description = "MCP service account email"
  value       = local.mcp_service_account
}

output "artifact_registry_url" {
  description = "Artifact Registry repository URL"
  value       = "${local.cloud_run_region}-docker.pkg.dev/${local.project_id}/${google_artifact_registry_repository.mcp.name}"
}

output "custom_domain" {
  description = "Custom domain for the MCP server"
  value       = local.custom_domain
}
