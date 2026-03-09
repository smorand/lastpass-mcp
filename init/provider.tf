terraform {
  required_version = ">= 1.0"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = ">= 6.0.0"
    }
  }

  # No backend for init - uses local state
}

provider "google" {
  project = local.project_id
  region  = local.location
}
