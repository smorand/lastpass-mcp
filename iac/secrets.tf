# OAuth Credentials Secret: Secret Manager for OAuth client credentials

# ============================================
# LOCALS
# ============================================

locals {
  # Secrets configuration from config.yaml
  secrets_config         = lookup(local.config, "secrets", {})
  oauth_credentials_name = lookup(local.secrets_config, "oauth_credentials", "oauth-credentials")
}

# ============================================
# SECRET MANAGER SECRET
# ============================================

resource "google_secret_manager_secret" "oauth_credentials" {
  secret_id = local.oauth_credentials_name

  replication {
    auto {}
  }

  labels = {
    environment = local.env
    managed_by  = "terraform"
    purpose     = "oauth-credentials"
  }
}

# ============================================
# OUTPUTS
# ============================================

output "oauth_secret_name" {
  description = "Secret Manager secret name for OAuth credentials"
  value       = google_secret_manager_secret.oauth_credentials.secret_id
}

output "oauth_secret_id" {
  description = "Secret Manager secret resource ID"
  value       = google_secret_manager_secret.oauth_credentials.id
}

# ============================================
# MANUAL SECRET VERSION CREATION
# ============================================
#
# After Terraform creates the secret, run:
#
#   gcloud secrets versions add scm-pwd-lastpass-oauth-creds \
#     --data-file=$HOME/.credentials/scm-pwd-lastpass.json \
#     --project=scmlastpass-mcp-prd
#
