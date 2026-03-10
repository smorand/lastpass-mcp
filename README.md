# LastPass MCP Server

A standalone Go server implementing the Model Context Protocol (MCP) for managing LastPass vault entries. AI assistants can authenticate with LastPass, search entries, view credentials, and create or update vault items through a secure OAuth 2.1 protected API.

The server communicates directly with the LastPass API, performing PBKDF2 key derivation and AES 256 encryption/decryption locally. It deploys to Google Cloud Run with managed SSL and custom domain support.

## Prerequisites

- **Go 1.26+**
- **GCP project** (for Cloud Run deployment)
- **Terraform** (for infrastructure provisioning)
- **Docker** (for container builds)
- **gcloud CLI** (for GCP authentication)

## Quick Start

### Build

```bash
make build
```

This compiles the binary for your current platform into `bin/`.

### Run Locally

```bash
# Start on default port 8080
make run ARGS="mcp"

# Start on a custom port
make run ARGS="mcp --port 3000"

# Start on all interfaces with a specific base URL
make run ARGS="mcp --host 0.0.0.0 --port 8080 --base-url https://example.com"
```

The server starts an HTTP server with:
- MCP endpoint at `/mcp` (OAuth2 protected)
- OAuth2 discovery at `/.well-known/oauth-protected-resource` and `/.well-known/oauth-authorization-server`
- Health check at `/health`

### Run Tests

```bash
make test
```

### Full Quality Check

```bash
make check    # Runs fmt + vet + lint + test
```

## Configuration Reference

Configuration is provided via CLI flags or environment variables. Flags take precedence.

| Flag                | Env Variable     | Default     | Description                              |
|---------------------|------------------|-------------|------------------------------------------|
| `--host`, `-H`      | `HOST`           | `localhost` | Address to bind the server               |
| `--port`, `-p`      | `PORT`           | `8080`      | Port to listen on                        |
| `--base-url`        | `BASE_URL`       | auto        | Public URL for OAuth callbacks           |
| `--secret-name`     | `SECRET_NAME`    |             | Secret Manager secret name               |
| `--secret-project`  | `SECRET_PROJECT` |             | GCP project for Secret Manager           |
| `--credential-file` |                  |             | Local OAuth credential file (fallback)   |
| `--environment`     | `ENVIRONMENT`    |             | Environment label (dev, stg, prd)        |
|                     | `KMS_KEY_NAME`   |             | Cloud KMS key for state encryption       |

When `--base-url` is not set, it defaults to `http://<host>:<port>`.

When `KMS_KEY_NAME` is set, the `DecryptionKey` field in persisted GCS state is encrypted with Cloud KMS before saving and decrypted after loading. This protects vault decryption keys at rest: even if the GCS bucket is compromised, the keys cannot be read without KMS access. If `KMS_KEY_NAME` is empty, keys are stored in plaintext (backward compatible).

## MCP Tool Reference

The server exposes 6 tools through the MCP protocol:

### lastpass_login

Authenticate to LastPass with email and master password.

```json
{"email": "user@example.com", "password": "masterpassword"}
```

Returns: `{"success": true, "username": "user@example.com", "message": "Login successful"}`

### lastpass_logout

Terminate the current session and invalidate the Bearer token.

Returns: `{"success": true, "message": "Logged out successfully"}`

### lastpass_search

Search vault entries by regex pattern (case insensitive). Matches against name, URL, and username.

```json
{"pattern": "github", "type": "password"}
```

Returns: `{"results": [{"id": "123", "name": "GitHub", "url": "https://github.com", "username": "user", "type": "password"}], "count": 1}`

The `type` field is optional and can be `password` or `paymentcard`.

### lastpass_show

Show full details of a vault entry by ID, including sensitive fields.

```json
{"id": "1234567890"}
```

Returns all fields for the entry, including `password` (for password type) or card details (for paymentcard type).

### lastpass_create

Create a new vault entry.

**Password entry:**
```json
{
  "type": "password",
  "name": "New Site",
  "url": "https://example.com",
  "username": "admin",
  "password": "s3cret"
}
```

**Payment card entry:**
```json
{
  "type": "paymentcard",
  "name": "My Visa",
  "cardholder_name": "John Doe",
  "card_number": "4111111111111111",
  "security_code": "123",
  "expiration_date": "12/2028"
}
```

### lastpass_update

Update an existing entry. Only provided fields are changed.

```json
{"id": "1234567890", "password": "newPassword!"}
```

## Deployment to Cloud Run

### First Time Setup

```bash
# 1. Bootstrap GCP resources (state bucket, service accounts, APIs)
make init-plan
make init-deploy

# 2. Deploy the application (Docker build + push + Cloud Run)
make plan
make deploy
```

### Subsequent Deployments

```bash
make deploy
```

This automatically rebuilds the Docker image if source files have changed, pushes to Artifact Registry, and updates the Cloud Run service.

### Teardown

```bash
make undeploy           # Remove application infrastructure
make init-destroy       # Remove bootstrap resources (interactive confirmation)
```

### Infrastructure Structure

The Terraform configuration is split into two directories:

- **init/**: One time bootstrap. Creates the GCS state bucket, enables GCP APIs, and provisions service accounts.
- **iac/**: Application infrastructure. Builds and pushes Docker images, deploys Cloud Run, configures domain mapping and DNS.

Both share `config.yaml` at the project root for consistent settings (GCP project, region, resource limits, domain).

## OAuth2 Flow Overview

The server implements OAuth 2.1 with Dynamic Client Registration to secure MCP endpoints:

1. **Discovery**: Client fetches `/.well-known/oauth-protected-resource` to find the authorization server, then `/.well-known/oauth-authorization-server` for endpoints.

2. **Registration**: Client registers via `POST /oauth/register` with redirect URIs. Receives a client ID and secret.

3. **Authorization**: Client redirects the user to `/oauth/authorize` with PKCE parameters. The server renders a LastPass login page.

4. **Authentication**: User enters LastPass email and master password. The server authenticates with the LastPass API, downloads and decrypts the vault.

5. **Token Exchange**: After successful login, the server redirects back with an authorization code. The client exchanges it at `/oauth/token` for a Bearer access token and refresh token.

6. **API Access**: The client includes the Bearer token in the `Authorization` header on all MCP requests. The server validates the token and injects the associated LastPass session.

7. **Token Refresh**: When the access token expires, the client uses the refresh token at `/oauth/token` to obtain a new one.

Supported OAuth2 scopes: `vault:read`, `vault:write`.
PKCE method: `S256` (SHA 256).

## Project Structure

```
cmd/lastpass-mcp/          Application entry point
internal/
  cli/                     Cobra CLI, flag parsing, server startup
  mcp/                     MCP server, OAuth2 endpoints, tool handlers
    templates/             HTML login page (embedded)
  lastpass/                LastPass API client, AES crypto, vault parser
  telemetry/               OpenTelemetry tracing (JSONL file exporter)
iac/                       Terraform: Cloud Run, Docker, secrets, DNS
init/                      Terraform: state backend, service accounts
config.yaml                Shared infrastructure configuration
Dockerfile                 Multi stage build (Go builder + Alpine runtime)
Makefile                   Build, test, deploy automation
```
