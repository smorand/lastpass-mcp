terraform {
  required_version = ">= 1.0"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 6.0"
    }
    docker = {
      source  = "kreuzwerker/docker"
      version = "~> 3.0"
    }
  }

backend "gcs" {
  bucket = "scmlastpass-iac-ew1-prd"
  prefix = "terraform/state"
}
}

provider "google" {
  project = local.project_id
  region  = local.location
}
