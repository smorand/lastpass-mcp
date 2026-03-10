# Cloud KMS keyring and crypto key for encrypting DecryptionKey in state
#
# Resources:
# - KMS keyring (regional)
# - Symmetric crypto key with 90-day rotation
# - IAM binding for Cloud Run service account

# ============================================
# KMS KEYRING
# ============================================

resource "google_kms_key_ring" "main" {
  name     = "${local.prefix}-${local.location_id}-${local.env}"
  location = local.location
}

# ============================================
# CRYPTO KEY
# ============================================

resource "google_kms_crypto_key" "state_encryption" {
  name            = "state-encryption"
  key_ring        = google_kms_key_ring.main.id
  purpose         = "ENCRYPT_DECRYPT"
  rotation_period = "7776000s" # 90 days
}

# ============================================
# IAM BINDING
# ============================================

resource "google_kms_crypto_key_iam_member" "cloudrun_encrypter_decrypter" {
  crypto_key_id = google_kms_crypto_key.state_encryption.id
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member        = "serviceAccount:${google_service_account.cloudrun.email}"
}

# ============================================
# OUTPUTS
# ============================================

output "kms_key_ring_id" {
  description = "KMS keyring resource ID"
  value       = google_kms_key_ring.main.id
}

output "kms_crypto_key_id" {
  description = "KMS crypto key resource ID"
  value       = google_kms_crypto_key.state_encryption.id
}

output "kms_key_name" {
  description = "Full KMS crypto key resource name for use as KMS_KEY_NAME env var"
  value       = google_kms_crypto_key.state_encryption.id
}
