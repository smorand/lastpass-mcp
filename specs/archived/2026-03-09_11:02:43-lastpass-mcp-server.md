# LastPass MCP Server -- Specification Document

> Generated on: 2026-03-09
> Version: 2.0
> Status: Draft

## 1. Executive Summary

LastPass MCP Server is a standalone Go MCP (Model Context Protocol) server that directly integrates with the LastPass API to provide vault operations via HTTP Streamable transport. It reimplements the LastPass protocol in pure Go (PBKDF2 key derivation, AES-256-CBC decryption/encryption, vault blob parsing) without any dependency on the `lpass` CLI binary.

The server exposes six MCP tools (login, logout, search, show, create, update) for managing password and payment card entries. Authentication is handled via an OAuth2 authorization server (RFC 8414, RFC 7591, RFC 9728) where the `/oauth/authorize` endpoint presents a login page for LastPass email and master password. On successful LastPass API login, the server issues Bearer tokens that map to per-user LastPass sessions (decryption key + session cookies).

The server is deployed on Google Cloud Run as a static Go binary in a Docker container at `https://lastpass.mcp.scm-platform.org/`. HTTPS is provided via a managed SSL certificate and custom domain mapping, both provisioned through Terraform. DNS is also managed via Terraform. The project follows the same structure and patterns as the google-contacts MCP server (config.yaml, Makefile, iac/ with Terraform).

The primary consumers are AI agents that search, read, create, and update LastPass vault entries programmatically.

## 2. Scope

### 2.1 In Scope
- MCP HTTP Streamable server (Go 1.26+, using `mcp-go` library)
- Direct LastPass API integration (no `lpass` CLI dependency)
  - PBKDF2 key derivation (SHA-256)
  - AES-256-CBC vault decryption/encryption
  - Vault blob download and parsing
  - Entry creation/update via LastPass upload endpoints
  - Session management (session cookies, CSRF tokens)
- OAuth2 Authorization Server (RFC 8414, RFC 7591, RFC 9728) with LastPass credential login page
- Six MCP tools: `login`, `logout`, `search`, `show`, `create`, `update`
- Support for two entry types: `password` and `paymentcard`
- Regexp-based search across URL, name, and username fields
- Complete entry display with all fields
- Create and update operations for both supported entry types
- Per-user session management (multi-user via Bearer token context injection)
- Retry with exponential backoff for LastPass API calls (1 minute max)
- Deployment on Google Cloud Run with Terraform IaC

### 2.2 Out of Scope (Non-Goals)
- Folder management (user does not use folders)
- Shared folder operations
- Entry deletion (`rm` command)
- Entry duplication
- Password generation
- Import/export functionality
- Attachment management
- Secure note types other than payment cards
- Multi-factor authentication (MFA) handling
- User management or enterprise features
- Horizontal scaling or multi-instance state sharing

## 3. User Personas & Actors

### AI Agent (Primary)
An LLM-based agent that calls MCP tools to search, read, create, and update credentials stored in LastPass. The agent authenticates via OAuth2 Bearer token. It never sees the master password directly; authentication happens through the OAuth2 authorize flow.

### Human Operator (Secondary)
A human who completes the OAuth2 authorization flow by entering their LastPass email and master password on the login page served by `/oauth/authorize`. This is the only direct interaction the human has with the server.

## 4. Usage Scenarios

### SC-001: OAuth2 Authentication Flow
**Actor:** Human Operator (via MCP client redirect)
**Preconditions:** Server is running on Cloud Run. MCP client has discovered the OAuth2 endpoints via `/.well-known/oauth-protected-resource`.
**Flow:**
1. MCP client discovers auth endpoints via `/.well-known/oauth-protected-resource` and `/.well-known/oauth-authorization-server`.
2. MCP client optionally registers via `POST /oauth/register` (or is auto-registered on first authorize request).
3. MCP client redirects the user to `/oauth/authorize?client_id=...&redirect_uri=...&response_type=code&state=...&code_challenge=...&code_challenge_method=S256`.
4. Server presents an HTML login page with fields for LastPass email and master password.
5. Human enters email and master password, submits the form.
6. Server calls the LastPass API iterations endpoint (`POST https://lastpass.com/iterations.php`) with the email to retrieve the PBKDF2 iteration count.
7. Server derives the login key using PBKDF2-SHA256 with the master password, email (as salt), and iteration count.
8. Server authenticates via `POST https://lastpass.com/login.php` with the derived login hash.
9. On success, server downloads and decrypts the vault blob.
10. Server creates a LastPass session (session cookies, decryption key, user email) and generates an OAuth2 authorization code.
11. Server redirects the user back to the MCP client's `redirect_uri` with the authorization code.
12. MCP client exchanges the code for a Bearer token via `POST /oauth/token`.
13. Bearer token is mapped to the LastPass session for subsequent MCP tool calls.
**Postconditions:** MCP client has a valid Bearer token. Server holds a LastPass session (decryption key, session cookies). MCP tools can now operate.
**Exceptions:**
- [EXC-001a]: Invalid credentials --> Server displays "Invalid master password or email" on the login page. No session is created.
- [EXC-001b]: Network unreachable (cannot contact LastPass servers) --> Server displays "Unable to connect to LastPass servers" error. Retries with exponential backoff up to 1 minute before failing.
- [EXC-001c]: Missing required OAuth2 parameters (client_id, redirect_uri, response_type) --> Server returns OAuth2 error response.
- [EXC-001d]: Invalid PKCE code_verifier at token exchange --> Server returns `invalid_grant` error.
- [EXC-001e]: Expired or invalid authorization code --> Server returns `invalid_grant` error.
**Cross-scenario notes:** After successful SC-001, all subsequent tool calls (SC-002 through SC-008) use the Bearer token from this flow.

### SC-002: Agent Searches for Entries
**Actor:** AI Agent
**Preconditions:** Valid Bearer token with active LastPass session.
**Flow:**
1. Agent calls `search` tool with a regexp pattern and optionally a type filter (`password` or `paymentcard`).
2. Server retrieves the cached vault data from the session (or re-downloads if stale).
3. Server applies the regexp pattern case-insensitively against name, URL, and username of each entry.
4. If `type` filter is specified, results are filtered to only that entry type.
5. Server returns a JSON array of matching entries with: id, name, username, url, and type.
**Postconditions:** No state change. Agent receives search results.
**Exceptions:**
- [EXC-002a]: No active session (invalid/expired Bearer token) --> Server returns HTTP 401 with `WWW-Authenticate` header.
- [EXC-002b]: Invalid regexp --> System returns an error: "Invalid regular expression: <details>."
- [EXC-002c]: No matches found --> System returns an empty array (not an error).

### SC-003: Agent Shows Entry Details
**Actor:** AI Agent
**Preconditions:** Valid Bearer token with active LastPass session. Agent knows the entry ID (from a prior search).
**Flow:**
1. Agent calls `show` tool with the entry ID.
2. Server looks up the entry in the decrypted vault data from the session.
3. Server returns the complete entry: id, name, url, username, password, notes, and any additional fields (for payment cards: cardholder name, card number, security code, start date, expiration date, type).
**Postconditions:** No state change.
**Exceptions:**
- [EXC-003a]: No active session --> HTTP 401 with `WWW-Authenticate` header.
- [EXC-003b]: Entry not found --> Error: "Entry with ID <id> not found."

### SC-004: Agent Creates a New Entry
**Actor:** AI Agent
**Preconditions:** Valid Bearer token with active LastPass session.
**Flow:**
1. Agent calls `create` tool with entry data. For `password` type: name, url, username, password, notes. For `paymentcard` type: name, cardholder name, card type, card number, security code, start date, expiration date, notes.
2. Server validates all required fields are present.
3. Server encrypts the entry data using AES-256-CBC with the session's decryption key.
4. Server uploads the encrypted entry to LastPass via the upload API endpoint.
5. Server refreshes the local vault cache.
6. Server returns the newly created entry ID.
**Postconditions:** New entry exists in the LastPass vault. Local vault cache is updated.
**Exceptions:**
- [EXC-004a]: No active session --> HTTP 401 with `WWW-Authenticate` header.
- [EXC-004b]: Missing required fields --> Error: "Missing required field: <field_name>."
- [EXC-004c]: Duplicate name exists --> The entry is created anyway (LastPass allows duplicate names).
- [EXC-004d]: LastPass API failure --> Error: "Failed to sync with LastPass servers." Retries with exponential backoff up to 1 minute.

### SC-005: Agent Updates an Existing Entry
**Actor:** AI Agent
**Preconditions:** Valid Bearer token with active LastPass session. Agent knows the entry ID.
**Flow:**
1. Agent calls `update` tool with the entry ID and fields to update. Only provided fields are modified; others remain unchanged.
2. Server reads the current entry from the decrypted vault cache.
3. Server merges the provided fields with existing values.
4. Server encrypts the updated entry and uploads it to LastPass via the upload API endpoint.
5. Server refreshes the local vault cache.
6. Server returns the updated entry.
**Postconditions:** Entry is updated in the vault. Local vault cache is updated.
**Exceptions:**
- [EXC-005a]: No active session --> HTTP 401 with `WWW-Authenticate` header.
- [EXC-005b]: Entry not found --> Error: "Entry with ID <id> not found."
- [EXC-005c]: LastPass API failure --> Error: "Failed to sync with LastPass servers." Retries with exponential backoff up to 1 minute.

### SC-006: Agent Logs Out
**Actor:** AI Agent
**Preconditions:** Valid Bearer token with active LastPass session.
**Flow:**
1. Agent calls `logout` tool.
2. Server invalidates the LastPass session (clears decryption key, session cookies, vault cache).
3. Server invalidates the Bearer token mapping.
4. Server returns confirmation.
**Postconditions:** Session is destroyed. Bearer token is invalidated. All subsequent tool calls with this token will return 401.
**Exceptions:**
- [EXC-006a]: Already logged out / invalid token --> System returns success (idempotent).

### SC-007: Agent Calls Tool Without Valid Token
**Actor:** AI Agent
**Preconditions:** No valid Bearer token (missing, expired, or invalidated).
**Flow:**
1. Agent sends an MCP request to `POST /` without a valid Bearer token.
2. Auth middleware detects missing/invalid token.
3. Server returns HTTP 401 with `WWW-Authenticate: Bearer resource_metadata="<base_url>/.well-known/oauth-protected-resource"`.
**Postconditions:** No state change.

### SC-008: Agent Triggers Login via MCP Tool
**Actor:** AI Agent
**Preconditions:** Valid Bearer token with an expired or invalid LastPass session (e.g., session cookies expired server-side).
**Flow:**
1. Agent calls `login` tool with email and master password.
2. Server calls the LastPass API iterations endpoint, derives the login key, and authenticates.
3. Server downloads and decrypts the vault blob.
4. Server updates the session associated with the Bearer token (new session cookies, refreshed decryption key).
5. Server returns success with logged-in username.
**Postconditions:** Active LastPass session re-established.
**Exceptions:**
- [EXC-008a]: Invalid credentials --> Error with details.
- [EXC-008b]: Already logged in with valid session --> System returns success without re-authenticating (idempotent).

## 5. Functional Requirements

### FR-001: MCP HTTP Streamable Server
- **Description:** The server must implement MCP protocol over HTTP Streamable transport.
- **Inputs:** HTTP requests conforming to MCP protocol.
- **Outputs:** MCP-compliant HTTP responses.
- **Business Rules:** Must use `mcp-go` library. Single binary. Configuration via YAML file with `--config` flag. Deployed on Google Cloud Run, port 8080.
- **Priority:** Must-have

### FR-002: LastPass Session Management
- **Description:** The server must maintain per-user LastPass sessions in memory. Each session holds the decryption key, session cookies, user email, and cached decrypted vault data. Sessions are keyed by Bearer token.
- **Inputs:** Successful LastPass API login.
- **Outputs:** Session stored in memory, mapped to a Bearer token.
- **Business Rules:** Sessions persist indefinitely while the server runs (no timeout). Sessions are destroyed on explicit logout. Sessions are per-Bearer-token (multi-user support). The decryption key and master password must never be written to disk. On server restart, all sessions are lost (users must re-authenticate).
- **Priority:** Must-have

### FR-003: Authentication State Detection
- **Description:** Before every vault operation, the auth middleware must verify the Bearer token maps to a valid LastPass session.
- **Inputs:** Bearer token from Authorization header.
- **Outputs:** LastPass session injected into request context, or HTTP 401 rejection.
- **Business Rules:** If no Bearer token is provided, return 401 with `WWW-Authenticate` header pointing to the protected resource metadata (RFC 9728). If the Bearer token does not map to a valid session, return 401 with `error="invalid_token"`.
- **Priority:** Must-have

### FR-004: Login Tool
- **Description:** MCP tool that authenticates (or re-authenticates) to LastPass.
- **Inputs:** `email` (string, required), `password` (string, required).
- **Outputs:** JSON object with `success` (bool) and `username` (string).
- **Business Rules:** Calls LastPass iterations endpoint, derives key via PBKDF2-SHA256, authenticates via LastPass login endpoint. On success, downloads and decrypts vault blob. Updates the session associated with the current Bearer token. If already logged in as the same user with a valid session, returns success without re-authenticating.
- **Priority:** Must-have

### FR-005: Logout Tool
- **Description:** MCP tool that terminates the LastPass session.
- **Inputs:** None.
- **Outputs:** JSON object with `success` (bool).
- **Business Rules:** Destroys the LastPass session (clears decryption key, session cookies, vault cache). Invalidates the Bearer-to-session mapping. Idempotent (succeeds even if already logged out).
- **Priority:** Must-have

### FR-006: Search Tool
- **Description:** MCP tool that searches vault entries by regexp.
- **Inputs:** `pattern` (string, required, a regular expression), `type` (string, optional, one of `password` or `paymentcard`).
- **Outputs:** JSON array of matching entries. Each entry contains: `id`, `name`, `url`, `username`, `type`.
- **Business Rules:** The regexp is matched case-insensitively against three fields: name, URL, and username. Entries are read from the decrypted vault cache in the session. If `type` is specified, results are filtered to only that entry type. Payment card entries are identified by having URL `http://sn` and a `NoteType` of `Credit Card` in their notes. Password entries are everything else.
- **Priority:** Must-have

### FR-007: Show Tool
- **Description:** MCP tool that displays full entry details.
- **Inputs:** `id` (string, required, the LastPass entry ID).
- **Outputs:** JSON object with all entry fields. For password type: `id`, `name`, `url`, `username`, `password`, `notes`, `type` ("password"), `last_modified`, `last_touch`. For paymentcard type: `id`, `name`, `type` ("paymentcard"), `cardholder_name`, `card_type`, `card_number`, `security_code`, `start_date`, `expiration_date`, `notes`, `last_modified`, `last_touch`.
- **Business Rules:** Reads from the decrypted vault cache. Parses secure note fields for payment card entries.
- **Priority:** Must-have

### FR-008: Create Tool
- **Description:** MCP tool that creates a new vault entry.
- **Inputs:** `type` (string, required, `password` or `paymentcard`). For `password`: `name` (required), `url` (optional, defaults to ""), `username` (optional, defaults to ""), `password` (optional, defaults to ""), `notes` (optional, defaults to ""). For `paymentcard`: `name` (required), `cardholder_name` (optional), `card_type` (optional), `card_number` (optional), `security_code` (optional), `start_date` (optional), `expiration_date` (optional), `notes` (optional).
- **Outputs:** JSON object with the created entry (same format as show).
- **Business Rules:** Encrypts entry data using AES-256-CBC with the session's decryption key. Uploads to LastPass via the upload API endpoint. Refreshes the vault cache after creation. Retries failed API calls with exponential backoff (1 minute max).
- **Priority:** Must-have

### FR-009: Update Tool
- **Description:** MCP tool that updates an existing vault entry.
- **Inputs:** `id` (string, required). Plus any subset of the fields accepted by create (depending on type). Only provided fields are updated.
- **Outputs:** JSON object with the updated entry (same format as show).
- **Business Rules:** Reads current entry from vault cache, merges provided fields, encrypts, and uploads to LastPass via the upload API endpoint. Refreshes vault cache after update. Retries failed API calls with exponential backoff (1 minute max).
- **Priority:** Must-have

### FR-010: OAuth2 Authorization Server
- **Description:** The server must implement an OAuth2 authorization server with a login page for LastPass credentials.
- **Inputs:** OAuth2 requests per RFC 8414, RFC 7591, RFC 9728.
- **Outputs:** OAuth2 responses (authorization codes, Bearer tokens, metadata).
- **Business Rules:**
  - Unprotected endpoints:
    - `GET /.well-known/oauth-protected-resource` (RFC 9728 metadata)
    - `GET /.well-known/oauth-authorization-server` (RFC 8414 metadata)
    - `POST /oauth/register` (RFC 7591 dynamic client registration)
    - `GET /oauth/authorize` (shows login page, accepts standard OAuth2 params)
    - `POST /oauth/authorize` (processes login form submission)
    - `POST /oauth/token` (code exchange, supports `authorization_code` grant type)
  - Protected endpoint: `POST /` (MCP, requires Bearer token)
  - Health check: `GET /health` (unprotected)
  - The `/oauth/authorize` endpoint renders an HTML login page (embedded in the binary) with email and master password fields.
  - On successful LastPass login, generates an authorization code and redirects to the client's `redirect_uri`.
  - PKCE (S256) must be supported.
  - Auto-register clients that are not pre-registered (same as google-contacts pattern).
  - Scopes supported: `vault:read`, `vault:write`.
  - OAuth2 credentials (the server's own client_id/secret for signing, if needed) are stored in Google Secret Manager with local file fallback for development.
- **Priority:** Must-have

### FR-011: LastPass API Client
- **Description:** The server must implement a direct LastPass API client in Go, without depending on the `lpass` CLI binary.
- **Inputs:** User email and master password.
- **Outputs:** Authenticated session with decryption key, session cookies, and decrypted vault data.
- **Business Rules:**
  - **Iterations lookup:** `POST https://lastpass.com/iterations.php` with `email` parameter. Returns the PBKDF2 iteration count.
  - **Key derivation:** PBKDF2-SHA256 with master password, email as salt, and the iteration count. Produces a 32-byte decryption key. The login hash is derived from the key (one additional PBKDF2-SHA256 round with the key as password and master password as salt, if iterations > 1; or SHA-256 hex of the key if iterations == 1).
  - **Login:** `POST https://lastpass.com/login.php` with email, login hash, iterations, and other required parameters. Returns session cookies and CSRF token.
  - **Vault download:** `GET https://lastpass.com/getaccts.php?requestsrc=cli&mobile=1&b64=1&hasplugin=3.0.23` with session cookies. Returns base64-encoded vault blob.
  - **Vault decryption:** Parse the binary blob format (chunk-based: AACT records for entries). Decrypt entry fields using AES-256-CBC with the decryption key (or per-entry sharing keys where applicable).
  - **Entry upload:** Use the appropriate LastPass API endpoint to create/update entries with encrypted field data.
  - **Retry logic:** All LastPass API calls must implement exponential backoff retry with a maximum total duration of 1 minute. Initial delay: 100ms, multiplier: 2x, max delay per retry: 10s.
- **Priority:** Must-have

### FR-012: Entry Type Detection
- **Description:** The system must reliably distinguish between password and payment card entries.
- **Inputs:** Parsed vault entry data.
- **Outputs:** Entry type string: `password` or `paymentcard`.
- **Business Rules:** An entry is a `paymentcard` if its URL is `http://sn` and its notes contain `NoteType:Credit Card`. All other entries are `password` type.
- **Priority:** Must-have

## 6. Non-Functional Requirements

### 6.1 Performance
- Tool response time must be under 5 seconds for search and show operations (reading from in-memory decrypted vault cache).
- Create and update operations must complete within 15 seconds (includes LastPass API upload + retry budget).
- Login may take up to 30 seconds due to PBKDF2 key derivation (high iteration counts) and vault download/decryption.
- The server must handle sequential MCP requests per session. Concurrent requests from different Bearer tokens (different users) must be handled concurrently.

### 6.2 Security
- The master password must never be logged, traced, or written to disk. It must be used only for key derivation and then discarded from memory.
- The decryption key must be held only in the session's in-memory state. It must never be written to disk.
- Entry passwords, card numbers, and security codes must never appear in traces or logs.
- OAuth2 Bearer tokens must be cryptographically random (minimum 32 bytes).
- PKCE (S256) must be supported and validated.
- The login page must be served over HTTPS (provided by Cloud Run).
- OAuth2 credentials (server's own signing keys, if applicable) must be stored in Google Secret Manager with local file fallback for development.
- Authorization codes must be single-use and expire after 10 minutes.
- Registered client data and authorization states must be cleaned up periodically (expired entries removed every minute).

### 6.3 Usability
- The login page must be functional without JavaScript (pure HTML form submission).
- Error messages must be clear and actionable.
- The login page must be a single HTML page embedded in the Go binary via `go:embed`. No external CSS/JS dependencies.

### 6.4 Reliability
- The server must detect expired LastPass sessions (e.g., server-side session cookie expiry from LastPass) and return appropriate errors prompting re-authentication.
- All LastPass API calls must use exponential backoff retry with a maximum total duration of 1 minute.
- On Cloud Run cold start, all sessions are empty. Users must re-authenticate.

### 6.5 Observability
- **Collector**: JSONL file (default)
- **Trace file path**: `traces/lastpass-mcp.jsonl`
- **What to trace**: MCP tool calls (INFO), LastPass API calls with endpoints but NOT credentials (INFO), authentication state changes (INFO), OAuth2 flow steps (INFO), errors (ERROR), retry attempts (WARNING)
- **Sensitive data exclusion**: Master password, decryption keys, entry passwords, card numbers, security codes, Bearer tokens must NEVER appear in traces or logs
- Structured logging via `slog` with environment-aware format: JSON in production (Cloud Run), text otherwise (detected via `ENVIRONMENT` env var)

### 6.6 Deployment
- Single Go binary, statically compiled (`CGO_ENABLED=0`)
- Docker container (multi-stage build: `golang:1.26` builder, `alpine:latest` runtime with ca-certificates)
- Google Cloud Run deployment:
  - Port: 8080
  - CPU: 1
  - Memory: 256Mi
  - Min instances: 0
  - Max instances: 3
  - Allow unauthenticated (OAuth2 handled at application level)
  - Timeout: 300s
- Custom domain: `https://lastpass.mcp.scm-platform.org/` (OAuth callback already configured at `/oauth/callback`)
- Managed SSL certificate provisioned via Terraform (`google_compute_managed_ssl_certificate`)
- DNS record managed via Terraform (CNAME or A record pointing to Cloud Run)
- Cloud Run domain mapping via Terraform (`google_cloud_run_v2_domain_mapping` or `google_cloud_run_domain_mapping`)
- Terraform IaC in `iac/` directory (Cloud Run, Artifact Registry, Secret Manager, SSL certificate, DNS, domain mapping)
- Terraform init in `init/` directory (state backend, service accounts)
- Configuration via `config.yaml` (same format as google-contacts)
- Makefile with targets: build, test, check, plan, deploy, undeploy

### 6.7 Scalability
- Multi-instance deployment is possible but sessions are per-instance (not shared). Users connecting to a different instance after scale-up will need to re-authenticate. This is acceptable for the initial deployment.

## 7. Data Model

### Entry (Password Type)
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| id | string | auto | LastPass unique ID |
| name | string | yes | Entry name |
| url | string | no | Site URL |
| username | string | no | Login username |
| password | string | no | Login password |
| notes | string | no | Free-text notes |
| type | string | auto | Always "password" |
| last_modified | string | auto | Last modification time (GMT) |
| last_touch | string | auto | Last access time (GMT) |

### Entry (Payment Card Type)
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| id | string | auto | LastPass unique ID |
| name | string | yes | Entry name |
| cardholder_name | string | no | Name on Card |
| card_type | string | no | Card network (Visa, Mastercard, etc.) |
| card_number | string | no | Card number |
| security_code | string | no | CVV/CVC |
| start_date | string | no | Card start date |
| expiration_date | string | no | Card expiration date |
| notes | string | no | Free-text notes |
| type | string | auto | Always "paymentcard" |
| last_modified | string | auto | Last modification time (GMT) |
| last_touch | string | auto | Last access time (GMT) |

### LastPass Session (In-Memory)
| Field | Type | Description |
|-------|------|-------------|
| user_email | string | LastPass account email |
| decryption_key | []byte | 32-byte AES key derived from master password (never written to disk) |
| session_cookies | []http.Cookie | LastPass session cookies for API calls |
| csrf_token | string | CSRF token for LastPass API mutations |
| vault_cache | []Entry | Decrypted vault entries |
| created_at | time.Time | Session creation time |

### OAuth2 Token Mapping (In-Memory)
| Field | Type | Description |
|-------|------|-------------|
| bearer_token | string | The issued Bearer token (cryptographically random) |
| session | *LastPassSession | Pointer to the associated LastPass session |
| client_id | string | OAuth2 client that obtained this token |
| created_at | time.Time | Token creation time |

### OAuth2 Registered Client (In-Memory)
| Field | Type | Description |
|-------|------|-------------|
| client_id | string | Unique client identifier |
| client_secret | string | Client secret (for client_secret_basic/post auth) |
| redirect_uris | []string | Registered redirect URIs |
| created_at | time.Time | Registration time |

### OAuth2 Authorization Code (In-Memory, Single-Use)
| Field | Type | Description |
|-------|------|-------------|
| code | string | The authorization code |
| client_id | string | Client that initiated the flow |
| redirect_uri | string | Redirect URI for this flow |
| code_challenge | string | PKCE code challenge |
| code_method | string | PKCE method (S256) |
| lastpass_session | *LastPassSession | The authenticated LastPass session |
| created_at | time.Time | Code creation time (expires after 10 min) |

### Configuration (config.yaml)
| Field | Type | Default | Description |
|-------|------|---------|-------------|
| prefix | string | "scmlastpass" | Resource naming prefix |
| project_name | string | "lastpass-mcp" | Project name |
| env | string | "prd" | Environment (dev, stg, prd) |
| gcp.project_id | string | required | GCP Project ID |
| gcp.location | string | "europe-west1" | Cloud Run region |
| gcp.resources.cloud_run.name | string | "lastpass-mcp" | Cloud Run service name |
| gcp.resources.cloud_run.cpu | string | "1" | CPU allocation |
| gcp.resources.cloud_run.memory | string | "256Mi" | Memory allocation |
| gcp.resources.cloud_run.min_instances | int | 0 | Minimum instances |
| gcp.resources.cloud_run.max_instances | int | 3 | Maximum instances |
| secrets.oauth_credentials | string | required | Secret Manager secret name for OAuth creds |
| parameters.log_level | string | "info" | Logging level |
| parameters.default_port | int | 8080 | Server listen port |
| parameters.base_url | string | "https://lastpass.mcp.scm-platform.org" | Public base URL for OAuth redirects |
| parameters.domain | string | "lastpass.mcp.scm-platform.org" | Custom domain for Cloud Run |
| parameters.dns_zone | string | required | Cloud DNS managed zone name for the domain |

## 8. Documentation Requirements

All documentation listed below must be created and maintained as part of this project.

### 8.1 README.md
- Project description, purpose, and audience
- Prerequisites (Go 1.26+, GCP project, Terraform)
- How to build, configure, and run the server
- Configuration reference (config.yaml fields)
- MCP tool reference with example calls
- Docker usage instructions
- Cloud Run deployment workflow

### 8.2 CLAUDE.md & .agent_docs/
- `CLAUDE.md`: Compact index with project overview, key commands, essential conventions, and documentation index referencing `.agent_docs/` files
- `.agent_docs/mcp-tools.md`: Detailed MCP tool specifications with input/output schemas
- `.agent_docs/architecture.md`: Server architecture, LastPass API client design, OAuth2 flow, session management
- `.agent_docs/lastpass-protocol.md`: LastPass API endpoints, PBKDF2 key derivation, AES-256-CBC encryption/decryption, vault blob format
- `.agent_docs/terraform.md`: Infrastructure documentation

### 8.3 docs/*
- `docs/setup.md`: Detailed setup guide including GCP project setup, Secret Manager configuration
- `docs/configuration.md`: Full configuration reference
- `docs/oauth2-flow.md`: OAuth2 authorization flow documentation with sequence diagram

## 9. Traceability Matrix

| Scenario | Functional Req | E2E Tests (Happy) | E2E Tests (Failure) | E2E Tests (Edge) |
|----------|---------------|-------------------|---------------------|-------------------|
| SC-001 | FR-010, FR-011, FR-002 | E2E-001 | E2E-002, E2E-003, E2E-004, E2E-005 | E2E-006 |
| SC-002 | FR-006, FR-003, FR-012 | E2E-010, E2E-011 | E2E-012, E2E-013 | E2E-014, E2E-015, E2E-016 |
| SC-003 | FR-007, FR-003, FR-012 | E2E-020, E2E-021 | E2E-022, E2E-023 | E2E-024 |
| SC-004 | FR-008, FR-003, FR-012, FR-011 | E2E-030, E2E-031 | E2E-032, E2E-033, E2E-034 | E2E-035, E2E-036 |
| SC-005 | FR-009, FR-003, FR-012, FR-011 | E2E-040, E2E-041 | E2E-042, E2E-043, E2E-044 | E2E-045, E2E-046 |
| SC-006 | FR-005, FR-002 | E2E-050 | E2E-051 | E2E-052 |
| SC-007 | FR-003, FR-002 | N/A | E2E-060 | E2E-061 |
| SC-008 | FR-004, FR-011, FR-002 | E2E-070 | E2E-071, E2E-072 | E2E-073 |

## 10. End-to-End Test Suite

All tests must be implemented in the `tests/` directory. Each feature must have tests covering happy paths, failure paths, edge cases, and error recovery. Tests use a mock LastPass API server (`httptest`) to avoid real API calls.

### 10.1 Test Summary

| Test ID | Category | Scenario | FR refs | Priority |
|---------|----------|----------|---------|----------|
| E2E-001 | Core Journey | SC-001 | FR-010, FR-011 | Critical |
| E2E-002 | Error | SC-001 | FR-010, FR-011 | Critical |
| E2E-003 | Error | SC-001 | FR-010, FR-011 | High |
| E2E-004 | Error | SC-001 | FR-010 | High |
| E2E-005 | Error | SC-001 | FR-010 | Medium |
| E2E-006 | Edge | SC-001 | FR-010, FR-002 | Medium |
| E2E-010 | Core Journey | SC-002 | FR-006, FR-012 | Critical |
| E2E-011 | Feature | SC-002 | FR-006, FR-012 | Critical |
| E2E-012 | Error | SC-002 | FR-006, FR-003 | Critical |
| E2E-013 | Error | SC-002 | FR-006 | High |
| E2E-014 | Edge | SC-002 | FR-006 | Medium |
| E2E-015 | Edge | SC-002 | FR-006, FR-012 | Medium |
| E2E-016 | Edge | SC-002 | FR-006 | Medium |
| E2E-020 | Core Journey | SC-003 | FR-007, FR-012 | Critical |
| E2E-021 | Feature | SC-003 | FR-007, FR-012 | Critical |
| E2E-022 | Error | SC-003 | FR-007, FR-003 | Critical |
| E2E-023 | Error | SC-003 | FR-007 | High |
| E2E-024 | Edge | SC-003 | FR-007 | Medium |
| E2E-030 | Core Journey | SC-004 | FR-008, FR-012 | Critical |
| E2E-031 | Feature | SC-004 | FR-008, FR-012 | Critical |
| E2E-032 | Error | SC-004 | FR-008, FR-003 | Critical |
| E2E-033 | Error | SC-004 | FR-008 | High |
| E2E-034 | Error | SC-004 | FR-008 | High |
| E2E-035 | Edge | SC-004 | FR-008 | Medium |
| E2E-036 | Edge | SC-004 | FR-008 | Medium |
| E2E-040 | Core Journey | SC-005 | FR-009, FR-012 | Critical |
| E2E-041 | Feature | SC-005 | FR-009, FR-012 | Critical |
| E2E-042 | Error | SC-005 | FR-009, FR-003 | Critical |
| E2E-043 | Error | SC-005 | FR-009 | High |
| E2E-044 | Error | SC-005 | FR-009 | High |
| E2E-045 | Edge | SC-005 | FR-009 | Medium |
| E2E-046 | Edge | SC-005 | FR-009 | Medium |
| E2E-050 | Core Journey | SC-006 | FR-005, FR-002 | Critical |
| E2E-051 | Error | SC-006 | FR-005 | Medium |
| E2E-052 | Edge | SC-006 | FR-005, FR-002 | Medium |
| E2E-060 | Error | SC-007 | FR-003, FR-002 | Critical |
| E2E-061 | Edge | SC-007 | FR-003 | Medium |
| E2E-070 | Core Journey | SC-008 | FR-004, FR-011 | Critical |
| E2E-071 | Error | SC-008 | FR-004, FR-011 | Critical |
| E2E-072 | Error | SC-008 | FR-004 | High |
| E2E-073 | Edge | SC-008 | FR-004, FR-002 | Medium |

### 10.2 Test Specifications

#### E2E-001: OAuth2 Full Flow with LastPass Login
- **Category:** Core Journey
- **Scenario:** SC-001 -- OAuth2 authentication flow
- **Requirements:** FR-010, FR-011
- **Preconditions:** Server running with mock LastPass API. No active sessions.
- **Steps:**
  - Given the server is running and the mock LastPass API is configured to accept valid credentials
  - When the test client fetches `GET /.well-known/oauth-protected-resource`
  - Then the response contains the `authorization_servers` array with the server's base URL
  - When the test client registers via `POST /oauth/register` with a redirect URI
  - Then the response contains a client_id and client_secret
  - When the test client requests `GET /oauth/authorize` with valid OAuth2 params and PKCE challenge
  - Then the server returns an HTML login page with email and password fields
  - When the login form is submitted with valid LastPass credentials
  - Then the server redirects to the client's redirect_uri with an authorization code
  - When the test client exchanges the code at `POST /oauth/token` with the PKCE verifier
  - Then the response contains an access_token of type Bearer
  - When the test client calls `POST /` (MCP endpoint) with the Bearer token
  - Then the request succeeds (200 OK)
- **Priority:** Critical

#### E2E-002: OAuth2 Login with Invalid LastPass Credentials
- **Category:** Error
- **Scenario:** SC-001
- **Requirements:** FR-010, FR-011
- **Preconditions:** Server running with mock LastPass API configured to reject credentials.
- **Steps:**
  - Given the server is running and the mock LastPass API rejects credentials
  - When the user submits invalid email/password on the login page
  - Then the login page re-renders with an error message containing "Invalid"
  - And no authorization code is issued
  - And no session is created
- **Priority:** Critical

#### E2E-003: OAuth2 Login with LastPass API Unreachable
- **Category:** Error
- **Scenario:** SC-001
- **Requirements:** FR-010, FR-011
- **Preconditions:** Server running. Mock LastPass API is down.
- **Steps:**
  - Given the server is running and the LastPass API endpoint is unreachable
  - When the user submits credentials on the login page
  - Then the server retries with exponential backoff
  - And after 1 minute total, the login page displays a connectivity error
- **Priority:** High

#### E2E-004: OAuth2 Token Exchange with Invalid PKCE
- **Category:** Error
- **Scenario:** SC-001
- **Requirements:** FR-010
- **Preconditions:** Server running. Authorization code has been issued.
- **Steps:**
  - Given a valid authorization code has been obtained
  - When the test client exchanges it at `POST /oauth/token` with an incorrect code_verifier
  - Then the response is an `invalid_grant` error
- **Priority:** High

#### E2E-005: OAuth2 Token Exchange with Expired Code
- **Category:** Error
- **Scenario:** SC-001
- **Requirements:** FR-010
- **Preconditions:** Server running. Authorization code was issued more than 10 minutes ago.
- **Steps:**
  - Given an authorization code was issued and then expired (simulated via direct state manipulation or time advancement)
  - When the test client tries to exchange it at `POST /oauth/token`
  - Then the response is an `invalid_grant` error
- **Priority:** Medium

#### E2E-006: OAuth2 Flow with Auto-Registered Client
- **Category:** Edge
- **Scenario:** SC-001
- **Requirements:** FR-010, FR-002
- **Preconditions:** Server running. No pre-registered client.
- **Steps:**
  - Given no client has been registered via `POST /oauth/register`
  - When a client directly requests `GET /oauth/authorize` with an unknown client_id
  - Then the server auto-registers the client and shows the login page
  - And the full OAuth2 flow completes successfully
- **Priority:** Medium

#### E2E-010: Search Passwords by Regexp
- **Category:** Core Journey
- **Scenario:** SC-002 -- Agent searches for entries
- **Requirements:** FR-006, FR-012
- **Preconditions:** Active session via Bearer token. Vault contains entries matching the pattern.
- **Steps:**
  - Given the user is authenticated and the vault contains entries with "github" in the name
  - When the agent calls `search` with pattern `github.*` via MCP with Bearer token
  - Then the response is a JSON array containing matching entries
  - And each entry has fields: id, name, url, username, type
  - And all entries have type "password"
- **Priority:** Critical

#### E2E-011: Search Payment Cards by Type Filter
- **Category:** Feature
- **Scenario:** SC-002
- **Requirements:** FR-006, FR-012
- **Preconditions:** Active session. Vault contains both password and payment card entries.
- **Steps:**
  - Given the vault contains password and paymentcard entries
  - When the agent calls `search` with pattern `.*` and type `paymentcard`
  - Then only entries with type "paymentcard" are returned
- **Priority:** Critical

#### E2E-012: Search Without Valid Bearer Token
- **Category:** Error
- **Scenario:** SC-002
- **Requirements:** FR-006, FR-003
- **Preconditions:** No valid Bearer token.
- **Steps:**
  - Given no Bearer token is provided (or an invalid one)
  - When the agent calls `search` with any pattern
  - Then the response is HTTP 401 with `WWW-Authenticate` header containing `resource_metadata` URL
- **Priority:** Critical

#### E2E-013: Search with Invalid Regexp
- **Category:** Error
- **Scenario:** SC-002
- **Requirements:** FR-006
- **Preconditions:** Active session.
- **Steps:**
  - Given the user is authenticated
  - When the agent calls `search` with pattern `[invalid`
  - Then the response is an error containing "Invalid regular expression"
- **Priority:** High

#### E2E-014: Search Returns Empty Results
- **Category:** Edge
- **Scenario:** SC-002
- **Requirements:** FR-006
- **Preconditions:** Active session.
- **Steps:**
  - Given the user is authenticated
  - When the agent calls `search` with a pattern that matches nothing (e.g., `xyznonexistent12345`)
  - Then the response is an empty JSON array (not an error)
- **Priority:** Medium

#### E2E-015: Search Matches Across Name, URL, and Username
- **Category:** Edge
- **Scenario:** SC-002
- **Requirements:** FR-006, FR-012
- **Preconditions:** Active session. Vault has entries where the pattern matches only URL or only username.
- **Steps:**
  - Given entry A has name "Work Email" with url "https://mail.example.com"
  - And entry B has name "Personal" with username "admin@example.com"
  - When the agent calls `search` with pattern `example\.com`
  - Then both entries A and B are returned
- **Priority:** Medium

#### E2E-016: Search is Case-Insensitive
- **Category:** Edge
- **Scenario:** SC-002
- **Requirements:** FR-006
- **Preconditions:** Active session.
- **Steps:**
  - Given the vault contains an entry named "GitHub"
  - When the agent calls `search` with pattern `github`
  - Then the entry is returned
- **Priority:** Medium

#### E2E-020: Show Password Entry
- **Category:** Core Journey
- **Scenario:** SC-003 -- Agent shows entry details
- **Requirements:** FR-007, FR-012
- **Preconditions:** Active session. Entry with known ID exists in vault cache.
- **Steps:**
  - Given a password entry exists with a known ID
  - When the agent calls `show` with that ID
  - Then the response contains id, name, url, username, password, notes, type ("password"), last_modified, last_touch
- **Priority:** Critical

#### E2E-021: Show Payment Card Entry
- **Category:** Feature
- **Scenario:** SC-003
- **Requirements:** FR-007, FR-012
- **Preconditions:** Active session. Payment card entry with known ID exists.
- **Steps:**
  - Given a paymentcard entry exists with a known ID
  - When the agent calls `show` with that ID
  - Then the response contains id, name, type ("paymentcard"), cardholder_name, card_type, card_number, security_code, start_date, expiration_date, notes
- **Priority:** Critical

#### E2E-022: Show Without Valid Bearer Token
- **Category:** Error
- **Scenario:** SC-003
- **Requirements:** FR-007, FR-003
- **Preconditions:** No valid Bearer token.
- **Steps:**
  - Given no valid Bearer token is provided
  - When the agent calls `show` with any ID
  - Then the response is HTTP 401 with `WWW-Authenticate` header
- **Priority:** Critical

#### E2E-023: Show Non-Existent Entry
- **Category:** Error
- **Scenario:** SC-003
- **Requirements:** FR-007
- **Preconditions:** Active session.
- **Steps:**
  - Given the user is authenticated
  - When the agent calls `show` with a non-existent ID (e.g., "999999999999")
  - Then the response is an error: "Entry with ID 999999999999 not found."
- **Priority:** High

#### E2E-024: Show Entry with Special Characters in Notes
- **Category:** Edge
- **Scenario:** SC-003
- **Requirements:** FR-007
- **Preconditions:** Active session. Entry with special characters (newlines, quotes, Unicode) in notes.
- **Steps:**
  - Given an entry exists with notes containing newlines, double quotes, and Unicode characters
  - When the agent calls `show` with that ID
  - Then the response contains the notes with all special characters preserved
- **Priority:** Medium

#### E2E-030: Create Password Entry
- **Category:** Core Journey
- **Scenario:** SC-004 -- Agent creates a new entry
- **Requirements:** FR-008, FR-012
- **Preconditions:** Active session. Mock LastPass API accepts upload.
- **Steps:**
  - Given the user is authenticated
  - When the agent calls `create` with type "password", name "TestSite", url "https://test.com", username "user@test.com", password "s3cret!", notes "test notes"
  - Then the mock LastPass API receives an encrypted entry upload
  - And the response contains the created entry with a non-zero id
  - And a subsequent `show` call returns the entry with all provided fields
- **Priority:** Critical

#### E2E-031: Create Payment Card Entry
- **Category:** Feature
- **Scenario:** SC-004
- **Requirements:** FR-008, FR-012
- **Preconditions:** Active session. Mock LastPass API accepts upload.
- **Steps:**
  - Given the user is authenticated
  - When the agent calls `create` with type "paymentcard", name "My Visa", cardholder_name "John Doe", card_type "Visa", card_number "4111111111111111", security_code "123", expiration_date "2028-12"
  - Then the response contains the created entry with type "paymentcard"
  - And the entry is present in the vault cache
- **Priority:** Critical

#### E2E-032: Create Without Valid Bearer Token
- **Category:** Error
- **Scenario:** SC-004
- **Requirements:** FR-008, FR-003
- **Preconditions:** No valid Bearer token.
- **Steps:**
  - Given no valid Bearer token is provided
  - When the agent calls `create` with any data
  - Then the response is HTTP 401 with `WWW-Authenticate` header
- **Priority:** Critical

#### E2E-033: Create with Missing Required Field (Name)
- **Category:** Error
- **Scenario:** SC-004
- **Requirements:** FR-008
- **Preconditions:** Active session.
- **Steps:**
  - Given the user is authenticated
  - When the agent calls `create` with type "password" but no name
  - Then the response is an error: "Missing required field: name."
- **Priority:** High

#### E2E-034: Create with Invalid Type
- **Category:** Error
- **Scenario:** SC-004
- **Requirements:** FR-008
- **Preconditions:** Active session.
- **Steps:**
  - Given the user is authenticated
  - When the agent calls `create` with type "securenote"
  - Then the response is an error indicating invalid type (must be "password" or "paymentcard")
- **Priority:** High

#### E2E-035: Create Entry with Empty Optional Fields
- **Category:** Edge
- **Scenario:** SC-004
- **Requirements:** FR-008
- **Preconditions:** Active session.
- **Steps:**
  - Given the user is authenticated
  - When the agent calls `create` with type "password" and name "MinimalEntry" only
  - Then the entry is created successfully with empty url, username, password, and notes
- **Priority:** Medium

#### E2E-036: Create Entry with Very Long Notes
- **Category:** Edge
- **Scenario:** SC-004
- **Requirements:** FR-008
- **Preconditions:** Active session.
- **Steps:**
  - Given the user is authenticated
  - When the agent calls `create` with notes of 40,000 characters
  - Then the entry is created successfully (LastPass max note length is 45,000)
- **Priority:** Medium

#### E2E-040: Update Password Entry
- **Category:** Core Journey
- **Scenario:** SC-005 -- Agent updates an existing entry
- **Requirements:** FR-009, FR-012
- **Preconditions:** Active session. An existing password entry with known ID in vault cache.
- **Steps:**
  - Given a password entry exists with id "12345"
  - When the agent calls `update` with id "12345" and password "newP@ss!"
  - Then the mock LastPass API receives an encrypted entry upload
  - And the response contains the updated entry with the new password
  - And the username and other fields remain unchanged
- **Priority:** Critical

#### E2E-041: Update Payment Card Entry
- **Category:** Feature
- **Scenario:** SC-005
- **Requirements:** FR-009, FR-012
- **Preconditions:** Active session. An existing payment card entry.
- **Steps:**
  - Given a paymentcard entry exists
  - When the agent calls `update` with only the expiration_date changed
  - Then the response contains the updated expiration_date
  - And all other fields remain unchanged
- **Priority:** Critical

#### E2E-042: Update Without Valid Bearer Token
- **Category:** Error
- **Scenario:** SC-005
- **Requirements:** FR-009, FR-003
- **Preconditions:** No valid Bearer token.
- **Steps:**
  - Given no valid Bearer token is provided
  - When the agent calls `update` with any data
  - Then the response is HTTP 401 with `WWW-Authenticate` header
- **Priority:** Critical

#### E2E-043: Update Non-Existent Entry
- **Category:** Error
- **Scenario:** SC-005
- **Requirements:** FR-009
- **Preconditions:** Active session.
- **Steps:**
  - Given the user is authenticated
  - When the agent calls `update` with a non-existent ID
  - Then the response is an error: "Entry with ID <id> not found."
- **Priority:** High

#### E2E-044: Update with No Fields Changed
- **Category:** Error
- **Scenario:** SC-005
- **Requirements:** FR-009
- **Preconditions:** Active session. Entry exists.
- **Steps:**
  - Given a password entry exists
  - When the agent calls `update` with just the ID and no other fields
  - Then the response is the unchanged entry (no error, idempotent)
- **Priority:** High

#### E2E-045: Update Only Name of Entry
- **Category:** Edge
- **Scenario:** SC-005
- **Requirements:** FR-009
- **Preconditions:** Active session.
- **Steps:**
  - Given a password entry exists with name "OldName"
  - When the agent calls `update` with name "NewName"
  - Then the entry name is updated to "NewName"
  - And all other fields remain unchanged
- **Priority:** Medium

#### E2E-046: Update Entry with Special Characters
- **Category:** Edge
- **Scenario:** SC-005
- **Requirements:** FR-009
- **Preconditions:** Active session.
- **Steps:**
  - Given a password entry exists
  - When the agent calls `update` with password containing special chars: `p@$$w0rd!#%&*<>"`
  - Then the password is stored correctly with all special characters preserved
- **Priority:** Medium

#### E2E-050: Logout Success
- **Category:** Core Journey
- **Scenario:** SC-006 -- Agent logs out
- **Requirements:** FR-005, FR-002
- **Preconditions:** Active session via Bearer token.
- **Steps:**
  - Given the user is authenticated with a valid Bearer token
  - When the agent calls `logout`
  - Then the response indicates success
  - And the session is destroyed (decryption key, cookies, vault cache cleared)
  - And subsequent MCP calls with the same Bearer token return 401
- **Priority:** Critical

#### E2E-051: Logout with LastPass API Failure
- **Category:** Error
- **Scenario:** SC-006
- **Requirements:** FR-005
- **Preconditions:** Active session. LastPass API is unreachable.
- **Steps:**
  - Given the user is authenticated but the LastPass API is unreachable
  - When the agent calls `logout`
  - Then the local session is still destroyed (defensive cleanup)
  - And the response indicates success
- **Priority:** Medium

#### E2E-052: Logout When Already Logged Out (Idempotent)
- **Category:** Edge
- **Scenario:** SC-006
- **Requirements:** FR-005, FR-002
- **Preconditions:** Bearer token exists but session was already destroyed.
- **Steps:**
  - Given the user's session was already destroyed (e.g., by a prior logout)
  - When the agent calls `logout` again with the same Bearer token
  - Then the response indicates success (idempotent)
- **Priority:** Medium

#### E2E-060: MCP Request Without Bearer Token
- **Category:** Error
- **Scenario:** SC-007 -- Agent calls tool without valid token
- **Requirements:** FR-003, FR-002
- **Preconditions:** No Bearer token provided.
- **Steps:**
  - Given no Authorization header is present
  - When the agent sends any MCP request to `POST /`
  - Then the response is HTTP 401
  - And the `WWW-Authenticate` header contains `resource_metadata` pointing to `/.well-known/oauth-protected-resource`
- **Priority:** Critical

#### E2E-061: MCP Request with Expired/Invalid Bearer Token
- **Category:** Edge
- **Scenario:** SC-007
- **Requirements:** FR-003
- **Preconditions:** Bearer token does not map to any session.
- **Steps:**
  - Given an invalid or expired Bearer token is provided
  - When the agent sends any MCP request to `POST /`
  - Then the response is HTTP 401
  - And the `WWW-Authenticate` header contains `error="invalid_token"`
- **Priority:** Medium

#### E2E-070: Login via MCP Tool (Re-authentication)
- **Category:** Core Journey
- **Scenario:** SC-008 -- Agent triggers login via MCP tool
- **Requirements:** FR-004, FR-011
- **Preconditions:** Valid Bearer token but LastPass session is stale/expired.
- **Steps:**
  - Given the user has a Bearer token but the LastPass session has expired
  - When the agent calls `login` with valid email and password via MCP
  - Then the server authenticates with the mock LastPass API
  - And the session is refreshed with new cookies and vault data
  - And the response contains success:true and the username
- **Priority:** Critical

#### E2E-071: Login via MCP Tool with Invalid Credentials
- **Category:** Error
- **Scenario:** SC-008
- **Requirements:** FR-004, FR-011
- **Preconditions:** Valid Bearer token. Mock LastPass API rejects credentials.
- **Steps:**
  - Given the user has a valid Bearer token
  - When the agent calls `login` with invalid credentials
  - Then the response contains success:false and an error message
  - And the session remains in its previous state (not destroyed)
- **Priority:** Critical

#### E2E-072: Login via MCP Tool with Missing Fields
- **Category:** Error
- **Scenario:** SC-008
- **Requirements:** FR-004
- **Preconditions:** Valid Bearer token.
- **Steps:**
  - Given the user has a valid Bearer token
  - When the agent calls `login` without email or password
  - Then the response is an error: "Missing required field: email" or "Missing required field: password"
- **Priority:** High

#### E2E-073: Login via MCP Tool When Already Logged In
- **Category:** Edge
- **Scenario:** SC-008
- **Requirements:** FR-004, FR-002
- **Preconditions:** Active session with valid credentials.
- **Steps:**
  - Given the user is already logged in as "user@example.com" with a valid session
  - When the agent calls `login` with the same email
  - Then the response indicates success without re-authenticating (idempotent)
- **Priority:** Medium

## 11. Open Questions & TBDs

All previously identified TBDs have been resolved:
- ~~TBD-001:~~ Sessions persist indefinitely while server runs. RESOLVED.
- ~~TBD-002:~~ HTTPS handled by Cloud Run. RESOLVED.
- ~~TBD-003:~~ No MFA support. RESOLVED.
- ~~TBD-004:~~ Retry with exponential backoff, 1 minute max. RESOLVED.

No open questions remain.

## 12. Glossary

| Term | Definition |
|------|-----------|
| MCP | Model Context Protocol, a standard for AI agent tool communication |
| HTTP Streamable | MCP transport over standard HTTP with streaming support |
| Vault | The encrypted LastPass password store |
| Secure Note | A LastPass entry type for structured data (used for payment cards) |
| KDF | Key Derivation Function, used by LastPass to derive encryption keys from the master password |
| PBKDF2 | Password-Based Key Derivation Function 2, the specific KDF algorithm used by LastPass (with SHA-256) |
| AES-256-CBC | Advanced Encryption Standard with 256-bit key in Cipher Block Chaining mode, used for vault encryption |
| mcp-go | Go library implementing MCP server protocol |
| Entry | A single record in the LastPass vault (password or payment card) |
| Bearer token | An OAuth2 access token presented in the HTTP Authorization header |
| PKCE | Proof Key for Code Exchange, an OAuth2 extension that prevents authorization code interception |
| RFC 8414 | OAuth 2.0 Authorization Server Metadata |
| RFC 7591 | OAuth 2.0 Dynamic Client Registration Protocol |
| RFC 9728 | OAuth 2.0 Protected Resource Metadata |
| Cloud Run | Google Cloud's serverless container platform |
| Terraform | Infrastructure-as-Code tool used for GCP resource provisioning |
| Secret Manager | Google Cloud service for storing and managing secrets |
