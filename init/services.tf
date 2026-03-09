# Enable required GCP services/APIs

resource "google_project_service" "required_apis" {
  for_each = toset(local.services)

  project            = local.project_id
  service            = each.value
  disable_on_destroy = false
}

# Output enabled services
output "enabled_services" {
  description = "List of enabled GCP services"
  value       = [for svc in google_project_service.required_apis : svc.service]
}
