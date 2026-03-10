# Terraform state backend resources

# GCS bucket for terraform state
resource "google_storage_bucket" "terraform_state" {
  name          = local.state_bucket_name
  location      = local.location
  force_destroy = false

  uniform_bucket_level_access = true

  versioning {
    enabled = true
  }

  lifecycle_rule {
    condition {
      num_newer_versions = 3
    }
    action {
      type = "Delete"
    }
  }

  labels = {
    environment = local.env
    managed_by  = "terraform"
  }
}

# Grant access to project owner
resource "google_storage_bucket_iam_member" "owner_access" {
  bucket = google_storage_bucket.terraform_state.name
  role   = "roles/storage.admin"
  member = local.project_owner
}

# Grant access to devops service account
resource "google_storage_bucket_iam_member" "devops_access" {
  bucket = google_storage_bucket.terraform_state.name
  role   = "roles/storage.admin"
  member = "serviceAccount:${google_service_account.devops.email}"
}

# Output state bucket name for backend configuration
output "state_bucket_name" {
  description = "GCS bucket name for terraform state"
  value       = google_storage_bucket.terraform_state.name
}

output "backend_config" {
  description = "Backend configuration for iac/provider.tf"
  value = <<-EOT
    backend "gcs" {
      bucket = "${google_storage_bucket.terraform_state.name}"
      prefix = "terraform/state"
    }
  EOT
}
