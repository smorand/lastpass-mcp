# Documentation Index

Comprehensive documentation for the LastPass MCP Server project.

## Reading Order

For newcomers, the recommended reading order is:

1. [Project Overview](overview.md) : What the project does, tech stack, quick start
2. [Architecture](architecture.md) : System design, component relationships, data flow
3. [Authentication](authentication.md) : OAuth 2.1 flow, LastPass auth, session management
4. [Vault Management](functionalities/vault-management.md) : MCP tools, entry types, error handling
5. [Session Persistence](functionalities/session-persistence.md) : GCS state, KMS encryption
6. [LastPass Protocol](functionalities/lastpass-protocol.md) : API endpoints, cryptography, vault format
7. [DevOps Toolchain](devops.md) : Build, test, CI/CD, container, observability
8. [Deployment](deployment.md) : Terraform, Cloud Run, environments, rollback

## Full Index

### Core

| Document                                                          | Description                                          |
|-------------------------------------------------------------------|------------------------------------------------------|
| [overview.md](overview.md)                                        | Project purpose, features, tech stack, quick start   |
| [architecture.md](architecture.md)                                | System architecture, package structure, design decisions |
| [authentication.md](authentication.md)                            | OAuth 2.1, LastPass auth, key derivation, IAM        |

### Functionalities

| Document                                                          | Description                                          |
|-------------------------------------------------------------------|------------------------------------------------------|
| [functionalities/vault-management.md](functionalities/vault-management.md) | MCP tools (login, search, show, create, update), entry types |
| [functionalities/session-persistence.md](functionalities/session-persistence.md) | GCS persistence, KMS encryption, save behavior |
| [functionalities/lastpass-protocol.md](functionalities/lastpass-protocol.md) | LastPass API, cryptography, vault blob format |

### Operations

| Document                                                          | Description                                          |
|-------------------------------------------------------------------|------------------------------------------------------|
| [devops.md](devops.md)                                            | Build system, testing, CI/CD, Docker, observability  |
| [deployment.md](deployment.md)                                    | Terraform, Cloud Run, environments, rollback, config |

## Last Updated

2026-03-10
