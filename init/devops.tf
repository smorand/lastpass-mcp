# DevOps service account for CI/CD deployments

resource "google_service_account" "devops" {
  account_id   = "${local.prefix}-devops-${local.env}"
  display_name = "DevOps Service Account for CI/CD"
  project      = local.project_id
}

resource "google_project_iam_member" "devops_role" {
  project = local.project_id
  role    = local.devops.role
  member  = "serviceAccount:${google_service_account.devops.email}"
}

output "devops_service_account" {
  description = "DevOps service account email"
  value       = google_service_account.devops.email
}

output "docker_registry_location" {
  description = "Docker registry location for auth configuration"
  value       = "${local.location}-docker.pkg.dev"
}
