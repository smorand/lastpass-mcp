# Conventions

## Code Organization

- Module name: `lastpass-mcp`
- Entry point: `cmd/lastpass-mcp/main.go` calls `cli.Execute()`
- All internal packages under `internal/` (not importable externally)
- Package naming: short, lowercase, single word (`cli`, `mcp`, `lastpass`, `telemetry`)

## Naming Patterns

- MCP tool names: `lastpass_<action>` (snake_case with lastpass prefix)
- Input/output types: `<Action>Input`, `<Action>Output` (e.g., `LoginInput`, `SearchOutput`)
- Context keys: custom `contextKey` type to avoid collisions
- Terraform resources: `<prefix>-<resource>-<env>` (e.g., `scmlastpass-cloudrun-prd`)
- Service accounts: `<prefix>-<service>-<env>` (e.g., `scmlastpass-cloudrun-prd`)

## Configuration Hierarchy

Flags take precedence over environment variables, which take precedence over defaults:
1. CLI flags (`--port`, `--host`, etc.)
2. Environment variables (`PORT`, `HOST`, etc.)
3. Default values (port 8080, host localhost)

## Error Handling

- Tool handlers return errors as `fmt.Errorf(...)` for validation failures
- Login failures are returned as `LoginOutput{Success: false, Message: "..."}` (not Go errors)
- All LastPass API calls use `RetryWithBackoff` with exponential backoff
- Permanent errors (invalid credentials, rate limiting) are wrapped in `permanentError` to stop retries
- The `permanentError` type implements `Unwrap()` for `errors.As()` compatibility

## Entry Type Detection

- Default type is `password`
- Payment card: NoteType field (index 29) == `Credit Card` AND URL == `http://sn`
- Payment card details are stored as key:value pairs in the Notes field

## OAuth2 Security Rules

- PKCE is mandatory (S256 only)
- Redirect URIs are validated against a hardcoded allowlist (not configurable)
- Authorization codes are single use with 10 minute TTL
- Tokens do not expire automatically (persist until logout or server restart)
- Client secrets do not expire
- All in memory state is protected by `sync.RWMutex`

## Infrastructure Rules

- Never use default GCP service accounts
- Config shared between Terraform init/ and iac/ via `config.yaml`
- init/ contains ONLY: state bucket, devops SA, API enablement
- Workload SAs and KMS resources are in iac/ (direct resource references)
- Docker builds are managed by Terraform (not manual)
- All GCS buckets use uniform bucket level access
