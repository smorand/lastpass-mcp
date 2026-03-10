# Makefile Documentation

## Overview

The Makefile follows the canonical Go project template with `define`/`eval` incremental build rules and full platform support.

## Standard Targets

| Target | Description |
|--------|-------------|
| `build` | Build all commands for current platform (incremental) |
| `build-all` | Build for all platforms + launcher scripts |
| `rebuild` / `rebuild-all` | Clean and rebuild |
| `run CMD=x ARGS='...'` | Build and run a command |
| `install` | Install to ~/.local/bin (or /usr/local/bin as root) |
| `install-launcher` | Install launcher scripts with all platform binaries |
| `uninstall` | Remove installed binaries |
| `test` | Run functional tests (tests/run_tests.sh) |
| `test-unit` | Run Go unit tests |
| `test-race` | Run Go unit tests with race detector |
| `test-all` | Run both functional and unit tests |
| `fmt` | Format code with go fmt |
| `vet` | Run go vet |
| `lint` | Run golangci-lint (falls back to go vet) |
| `check` | fmt + vet + lint + test-all |
| `docker-build` | Build Docker images for all commands |
| `docker-push` | Push Docker images to registry |
| `docker` | Build and push |
| `run-up` | Build Docker images + docker compose up |
| `run-down` | docker compose down |
| `init-mod` | Initialize go.mod |
| `init-deps` | Initialize go.mod + download deps |
| `clean` | Remove build artifacts |
| `clean-all` | Remove build artifacts + go.mod/go.sum |
| `list-commands` | List available commands |
| `info` / `help` | Show project info / help |

## Project-Specific Targets (Terraform)

| Target | Description |
|--------|-------------|
| `plan` | Plan main infrastructure (iac/) |
| `deploy` | Deploy main infrastructure |
| `undeploy` | Destroy main infrastructure |
| `init-plan` | Plan initialization resources (init/) |
| `init-deploy` | Deploy initialization |
| `init-destroy` | Destroy initialization (dangerous) |
| `terraform-help` | Show Terraform help |
| `check-init` | Verify init has been deployed |
| `update-backend` | Regenerate iac/provider.tf from init output |
| `configure-docker-auth` | Configure Artifact Registry auth |

## Key Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `COMMANDS` | Auto-detected from cmd/ | debug-vault, lastpass-mcp |
| `MODULE_NAME` | Go module name | lastpass-mcp |
| `BUILD_DIR` | Output directory | bin |
| `MAKE_DOCKER_PREFIX` | Docker registry prefix | empty |
| `DOCKER_TAG` | Docker image tag | latest |
| `HAS_INTERNAL` | Whether internal/ exists | auto-detected |
| `HAS_DATA` | Whether data/ exists | auto-detected |
| `HAS_FUNCTIONAL_TESTS` | Whether tests/run_tests.sh exists | auto-detected |

## How Incremental Builds Work

The Makefile uses `define`/`eval` to generate per-command, per-platform build rules. Each binary (`bin/<cmd>-<os>-<arch>`) depends on `go.sum` and all `.go` source files. Only rebuilds when sources change.
