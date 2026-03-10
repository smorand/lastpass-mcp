# Project Overview

## Purpose and Business Context

LastPass MCP Server is a standalone Go server that bridges AI assistants (such as Claude) with the LastPass password manager through the Model Context Protocol (MCP). It enables AI agents to authenticate with LastPass, search vault entries, view credentials, and create or update password and payment card entries, all through a secure, standards compliant API.

The server communicates directly with the LastPass API, performing all cryptographic operations locally: PBKDF2 key derivation, AES 256 encryption and decryption. No master passwords or vault decryption keys are ever transmitted to third parties.

## Key Features

- **Vault Management**: Search, view, create, and update password and payment card entries
- **Direct LastPass API Integration**: No CLI wrapper or browser extension dependency
- **Local Cryptography**: PBKDF2 key derivation and AES 256 CBC/ECB encryption handled in process
- **OAuth 2.1 Authorization**: Dynamic Client Registration, PKCE (S256), Bearer tokens
- **Session Persistence**: GCS backed state with optional Cloud KMS encryption for decryption keys at rest
- **Out of Band Verification**: Supports LastPass MFA push/email approval polling
- **Cloud Native Deployment**: Docker container on Google Cloud Run with managed SSL and custom domain
- **Two Phase Terraform**: Separate bootstrap (init/) and application (iac/) infrastructure
- **Observability**: OpenTelemetry tracing with JSONL file exporter

## Tech Stack

| Component         | Technology                                  |
|-------------------|---------------------------------------------|
| Language          | Go 1.26                                     |
| MCP SDK           | github.com/modelcontextprotocol/go-sdk v1.4 |
| CLI Framework     | Cobra                                       |
| HTTP Server       | Go stdlib `net/http`                        |
| Cryptography      | AES 256 CBC/ECB, PBKDF2 SHA256              |
| Cloud Provider    | Google Cloud Platform (Cloud Run, GCS, KMS, Secret Manager, Artifact Registry, Cloud DNS) |
| Infrastructure    | Terraform (HCL)                             |
| Container         | Docker (multi stage, Alpine runtime)        |
| Observability     | OpenTelemetry                               |

## Quick Start

### Prerequisites

- Go 1.26+
- Docker (for container builds)
- Terraform (for infrastructure provisioning)
- gcloud CLI (for GCP authentication)
- A GCP project (for Cloud Run deployment)

### Build and Run Locally

```bash
# Build the binary
make build

# Start on default port 8080
make run ARGS="mcp"

# Start on a custom port
make run ARGS="mcp --port 3000"
```

The server starts with:
- MCP endpoint at `/mcp` (OAuth2 protected)
- OAuth2 discovery at `/.well-known/oauth-protected-resource` and `/.well-known/oauth-authorization-server`
- Health check at `/health`

### Run Tests

```bash
make test           # Run all tests
make check          # Run fmt + vet + lint + test
```

### Deploy to Cloud Run

```bash
# First time: bootstrap infrastructure
make init-plan && make init-deploy

# Deploy application
make plan && make deploy
```

See [Deployment](deployment.md) for detailed instructions.
