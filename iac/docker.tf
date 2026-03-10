# Docker Image Build: local build + push to Artifact Registry

# ============================================
# DOCKER PROVIDER CONFIGURATION
# ============================================

provider "docker" {
  registry_auth {
    address     = "${local.cloud_run_region}-docker.pkg.dev"
    config_file = pathexpand("~/.docker/config.json")
  }
}

# ============================================
# DOCKER IMAGE BUILD (LOCAL)
# ============================================

resource "docker_image" "mcp" {
  name = local.mcp_image

  build {
    context    = "${path.root}/.."
    dockerfile = "Dockerfile"

    label = {
      "org.opencontainers.image.source" = "https://github.com/smorand/lastpass-mcp"
      "org.opencontainers.image.title"  = "lastpass-mcp"
      "environment"                      = local.env
      "managed_by"                       = "terraform"
    }
  }

  triggers = {
    dockerfile_hash = filesha256("${path.root}/../Dockerfile")
    go_mod_hash     = filesha256("${path.root}/../go.mod")
    go_sum_hash     = filesha256("${path.root}/../go.sum")
    main_hash       = filesha256("${path.root}/../cmd/lastpass-mcp/main.go")
    cli_hash        = filesha256("${path.root}/../internal/cli/cli.go")
    lastpass_client  = filesha256("${path.root}/../internal/lastpass/client.go")
    lastpass_crypto  = filesha256("${path.root}/../internal/lastpass/crypto.go")
    lastpass_vault   = filesha256("${path.root}/../internal/lastpass/vault.go")
    mcp_server_hash = filesha256("${path.root}/../internal/mcp/server.go")
    mcp_oauth2_hash = filesha256("${path.root}/../internal/mcp/oauth2.go")
  }
}

# ============================================
# DOCKER IMAGE PUSH (TO ARTIFACT REGISTRY)
# ============================================

resource "docker_registry_image" "mcp" {
  name = docker_image.mcp.name

  keep_remotely = true

  triggers = {
    image_id = docker_image.mcp.image_id
  }

  depends_on = [google_artifact_registry_repository.mcp]
}

# ============================================
# OUTPUTS
# ============================================

output "docker_image" {
  description = "Full Docker image URL"
  value       = docker_registry_image.mcp.name
}

output "docker_image_digest" {
  description = "Docker image SHA256 digest"
  value       = docker_registry_image.mcp.sha256_digest
}
