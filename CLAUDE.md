# LastPass MCP Server

## Overview

A standalone Go MCP (Model Context Protocol) server that enables AI assistants to manage LastPass vault entries remotely. Authenticates directly with the LastPass API using PBKDF2 key derivation and AES 256 encryption. Deployed to Google Cloud Run with OAuth 2.1 authorization.

**Tech stack:** Go 1.26, MCP Go SDK, Cobra CLI, OpenTelemetry, Terraform (GCP)

## Key Commands

```bash
# Build
make build                    # Build for current platform
make build-all                # Build for all platforms (linux, darwin amd64/arm64)

# Test and Quality
make test                     # Run all tests
make check                    # Run fmt + vet + lint + test
make fmt                      # Format code
make vet                      # Run go vet

# Run locally
make run ARGS="mcp"                              # Default (localhost:8080)
make run ARGS="mcp --port 3000"                   # Custom port
make run ARGS="mcp --host 0.0.0.0 --port 8080"   # All interfaces

# Deploy (Terraform)
make init-plan                # Plan initialization (state backend, service accounts)
make init-deploy              # Deploy initialization resources
make plan                     # Plan main infrastructure
make deploy                   # Build Docker + push + deploy to Cloud Run
make undeploy                 # Destroy main infrastructure

# Install
make install                  # Install binary to ~/.local/bin
```

## Project Structure

```
cmd/lastpass-mcp/             Entry point
internal/
  cli/                        Cobra CLI setup and flag parsing
  mcp/                        MCP server, OAuth2 endpoints, tool handlers
    templates/                 HTML login page template
  lastpass/                    LastPass API client, crypto, vault parsing
  telemetry/                   OpenTelemetry tracing
iac/                          Terraform: Cloud Run, Artifact Registry, secrets, DNS
init/                         Terraform: state backend, service accounts, API enablement
specs/                        Design specifications
config.yaml                   Shared config for prefix, GCP project, resources, parameters
```

## Conventions

- Module name: `lastpass-mcp`
- Entry types: `password` and `paymentcard`
- Payment card entries use URL `http://sn` as a sentinel value
- Vault fields are encrypted with AES 256 CBC (or ECB for legacy) and base64 encoded
- OAuth2 state is stored in memory (maps with mutex protection)
- Config shared between Terraform init/ and iac/ via `config.yaml`
- Never use default GCP service accounts; custom ones are created in init/

## Environment Variables

| Variable       | Description                        | Default     |
|----------------|------------------------------------|-------------|
| HOST           | Bind address                       | localhost   |
| PORT           | Listen port                        | 8080        |
| BASE_URL       | Public URL for OAuth callbacks     | auto        |
| SECRET_PROJECT | GCP project for Secret Manager     |             |
| SECRET_NAME    | Secret name for OAuth credentials  |             |
| ENVIRONMENT    | Environment label (dev, stg, prd)  |             |
| PROJECT_ID     | GCP project ID (fallback)          |             |
| KMS_KEY_NAME   | Cloud KMS key for encrypting state |             |

## Documentation Index

| File                                    | Contents                                     |
|-----------------------------------------|----------------------------------------------|
| `.agent_docs/architecture.md`           | Server architecture, package roles, lifecycle |
| `.agent_docs/lastpass-protocol.md`      | LastPass API, crypto, vault blob format       |
| `.agent_docs/mcp-tools.md`             | All 6 MCP tools with schemas and examples     |
| `.agent_docs/terraform.md`             | Infrastructure, init vs iac, deployment       |
