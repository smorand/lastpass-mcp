# Service accounts (NEVER use default service accounts)

locals {
  service_accounts = {
    cloudbuild = "${local.prefix}-cloudbuild-${local.env}"
    cloudrun   = "${local.prefix}-cloudrun-${local.env}"
  }
}

# Cloud Build service account
resource "google_service_account" "cloudbuild" {
  account_id   = local.service_accounts.cloudbuild
  display_name = "Cloud Build Service Account"
  description  = "Custom service account for Cloud Build (never use default)"
}

# Cloud Build IAM permissions
resource "google_project_iam_member" "cloudbuild_builder" {
  project = local.project_id
  role    = "roles/cloudbuild.builds.builder"
  member  = "serviceAccount:${google_service_account.cloudbuild.email}"
}

resource "google_project_iam_member" "cloudbuild_storage_admin" {
  project = local.project_id
  role    = "roles/storage.admin"
  member  = "serviceAccount:${google_service_account.cloudbuild.email}"
}

# Cloud Run service account
resource "google_service_account" "cloudrun" {
  account_id   = local.service_accounts.cloudrun
  display_name = "Cloud Run Service Account"
  description  = "Custom service account for Cloud Run services"
}

# Cloud Run IAM permissions
resource "google_project_iam_member" "cloudrun_viewer" {
  project = local.project_id
  role    = "roles/viewer"
  member  = "serviceAccount:${google_service_account.cloudrun.email}"
}

# Outputs
output "service_accounts" {
  description = "Created service account emails"
  value = {
    cloudbuild = google_service_account.cloudbuild.email
    cloudrun   = google_service_account.cloudrun.email
  }
}

# Output Docker registry location for auth configuration
output "docker_registry_location" {
  description = "Docker registry location for auth configuration"
  value       = "${local.location}-docker.pkg.dev"
}
