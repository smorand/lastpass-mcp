locals {
  # Load configuration from config.yaml
  config = yamldecode(file("${path.root}/../config.yaml"))

  # Global fields
  prefix = local.config.prefix
  env    = local.config.env

  # GCP configuration
  gcp = lookup(local.config, "gcp", {})

  # GCP Project ID (explicit from config, not computed)
  project_id = local.gcp.project_id

  # GCP Location (can be multi-region or regional)
  location = local.gcp.location

  # Detect if multi-region
  is_multi_region = contains(["us", "eu", "asia"], local.location)

  # Compute location_id for resource naming
  location_id = local.is_multi_region ? local.location : (
    "${substr(local.location, 0, 1)}${substr(split("-", local.location)[1], 0, 1)}${regex("\\d+", local.location)}"
  )

  # Cloud Run region (from resources config or use location if regional)
  cloud_run_config = lookup(lookup(local.gcp, "resources", {}), "cloud_run", {})
  cloud_run_region = lookup(local.cloud_run_config, "region", local.is_multi_region ? "us-central1" : local.location)

  # Services to enable
  services = lookup(local.gcp, "services", [])

  # GCP-specific resources with defaults
  gcp_resources = lookup(local.gcp, "resources", {})

  # GCP-specific parameters with defaults
  gcp_parameters = lookup(local.gcp, "parameters", {})

  # Merge with global resources/parameters
  resources = merge(
    lookup(local.config, "resources", {}),
    local.gcp_resources
  )

  parameters = merge(
    lookup(local.config, "parameters", {}),
    local.gcp_parameters
  )
}
