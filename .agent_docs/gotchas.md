# Gotchas

## DecryptionKey Serialization

The `Session.DecryptionKey` field intentionally has no JSON tag (`DecryptionKey []byte`). This prevents accidental serialization via `encoding/json`. However, the persistence layer (`persistence.go`) uses a separate `persistedSession` struct that explicitly includes `decryption_key` for controlled serialization to GCS. If you add a JSON tag to `Session.DecryptionKey`, it will leak vault keys in API responses.

## ACCT Field Indices

The vault parser uses hardcoded field indices from the lastpass-cli source code (`blob.c`). The sub items within ACCT chunks use size-value format (no tag), so fields MUST be read by position. Key indices: 0=ID, 1=Name, 2=Group, 3=URL, 4=Notes, 7=Username, 8=Password, 12=LastTouch, 29=NoteType, 31=LastModified. Getting an index wrong will decrypt the wrong field, producing garbage.

## Payment Card URL Sentinel

Payment card entries always have URL set to `http://sn`. This is a LastPass convention for Secure Notes. When creating a payment card via the API, the server hardcodes this URL. Do not change it or the entry will not be recognized as a payment card.

## buildPaymentCardNotes Uses "Language" Instead of "Name on Card"

In `server.go`, the `buildPaymentCardNotes` function writes `Language:` instead of `Name on Card:` for the cardholder name field. This appears to be a bug (the parse function in `vault.go` reads `Name on Card:` key). Creating a payment card entry may not round trip the cardholder name correctly.

## OAuth2 Token Storage

Both access tokens and refresh tokens are stored in the same `tokens` map. The refresh token and access token for a given session point to the same `TokenMapping` struct. When refreshing, the old refresh token is deleted and new access+refresh tokens are added. There is no separate refresh token store.

## Redirect URI Allowlist is Hardcoded

The `allowedRedirectHosts` and `allowedExactRedirectURIs` variables in `oauth2.go` are compile time constants. Adding new redirect URIs requires a code change and redeployment. There is no runtime configuration for this.

## KMS Migration: Graceful Degradation

When `KMS_KEY_NAME` is newly set but existing state was stored in plaintext, `decryptKey` catches the KMS decryption error and returns the raw bytes. This silently assumes the data is plaintext. On the next save, all keys will be encrypted. However, if the data is corrupted (not valid plaintext AND not valid KMS ciphertext), the session will have garbage decryption keys.

## Docker Build Triggers

The Terraform Docker build only monitors specific source files for changes (listed in `docker.tf` triggers). If you add new source files (e.g., a new package), you must add their hash to the triggers block, or changes to those files will not trigger a rebuild.

## init-deploy Auto Updates provider.tf

Running `make init-deploy` automatically runs `update-backend` which overwrites `iac/provider.tf` from `iac/provider.tf.template`. If you manually edit `provider.tf`, your changes will be lost on the next `init-deploy`.

## Token Expiry is Cosmetic

The token response includes `expires_in: 86400` (24 hours), but the server does not actually enforce expiry. Tokens remain valid until logout or server restart. The `expires_in` field is only for client side information.
