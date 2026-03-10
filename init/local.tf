locals {
  # Load configuration from config.yaml
  config_file = yamldecode(file("${path.root}/../config.yaml"))
  config      = local.config_file

  # Global fields
  prefix = local.config.prefix
  env    = local.config.env

  # GCP configuration
  gcp = lookup(local.config, "gcp", {})

  # GCP Project ID (explicit from config)
  project_id = local.gcp.project_id

  # GCP Location
  location = local.gcp.location

  # Detect if multi-region
  is_multi_region = contains(["us", "eu", "asia"], local.location)

  # Compute location_id for naming
  location_id = local.is_multi_region ? local.location : (
    "${substr(local.location, 0, 1)}${substr(split("-", local.location)[1], 0, 1)}${regex("\\d+", local.location)}"
  )

  # State backend naming (uses prefix-iac-location_id-env)
  state_bucket_name = "${local.prefix}-iac-${local.location_id}-${local.env}"

  # Services to enable
  services = lookup(local.gcp, "services", [
    "storage.googleapis.com",
    "logging.googleapis.com",
    "cloudresourcemanager.googleapis.com",
    "iam.googleapis.com"
  ])
}
