# Architecture

## Server Architecture

```
                    MCP Client (Claude, etc.)
                           |
                    HTTPS (Bearer token)
                           |
                    +------v------+
                    |  Cloud Run  |
                    +------+------+
                           |
              +------------+------------+
              |                         |
     OAuth2 Endpoints            MCP Endpoint
     (no auth required)         (/mcp, /mcp/)
              |                         |
              |                  Auth Middleware
              |                  (Bearer token
              |                   validation)
              |                         |
              v                         v
      +-------+-------+       +--------+--------+
      | OAuth2Server  |       |   MCP Server    |
      | (in memory    |       | (go-sdk/mcp)    |
      |  state maps)  |       |                 |
      +-------+-------+       +--------+--------+
              |                         |
              |           +-------------+-------------+
              |           |             |             |
              |      Tool Handlers    Tool Handlers  ...
              |           |             |
              v           v             v
        +-----+-----+  +-+-------------+-+
        | LastPass   |  | LastPass Client  |
        | Login API  |  | (vault ops)      |
        +-----+------+ +--+----------+----+
              |            |          |
        Session +    Download    Create/Update
        Vault       Vault Blob   Entry (API)
```

## Package Structure and Responsibilities

### cmd/lastpass-mcp
Entry point. Calls `cli.Execute()` which runs the Cobra root command.

### internal/cli
Defines the CLI using Cobra. The `mcp` subcommand configures and starts the server. Flags and environment variables are merged here (flags take precedence, then env vars, then defaults).

### internal/mcp
Core of the application. Contains two main files:

**server.go**: MCP server setup and tool registration. Implements all six tool handlers (login, logout, search, show, create, update). Manages the HTTP mux, auth middleware, health endpoint, and graceful shutdown. Uses `context.WithValue` to thread session and bearer token through request handlers.

**oauth2.go**: Full OAuth 2.1 Authorization Server. Implements:
  - RFC 9728: Protected Resource Metadata
  - RFC 8414: Authorization Server Metadata
  - RFC 7591: Dynamic Client Registration
  - Authorization Code flow with PKCE (S256)
  - Token refresh

All state (clients, auth states, auth codes, token mappings) is stored in memory with `sync.RWMutex` protection. Tokens and clients are persisted to Firestore (per document writes with KMS encryption for DecryptionKey). A background goroutine cleans up expired states and codes every minute.

**templates/login.html**: Embedded HTML login page rendered during the OAuth authorize flow.

### internal/lastpass
LastPass API client and cryptography:

**client.go**: HTTP client for the LastPass API. Handles iteration lookup, authentication, vault download, entry creation, and updates. All API calls use `RetryWithBackoff` for resilience.

**crypto.go**: PBKDF2 key derivation, AES 256 CBC encryption/decryption, AES 256 ECB decryption (legacy), PKCS7 padding. Provides `DecryptField` which auto detects CBC vs ECB field format.

**vault.go**: Binary vault blob parser. Iterates over chunks (4 byte tag + 4 byte size + data), extracts ACCT chunks, and decrypts fields by index. Also parses payment card notes from structured key:value lines.

**retry.go**: Exponential backoff helper. Starts at 500ms, doubles per attempt, respects context cancellation, and stops after a configurable max duration.

### internal/telemetry
OpenTelemetry setup. Exports traces as JSONL to a local file. Provides `StartSpan` and `EndSpan` helpers.

## OAuth2 Flow

1. Client discovers auth server via `GET /.well-known/oauth-protected-resource`
2. Client fetches metadata from `GET /.well-known/oauth-authorization-server`
3. Client registers via `POST /oauth/register` (Dynamic Client Registration)
4. Client redirects user to `GET /oauth/authorize` with PKCE parameters
5. Server renders a LastPass login page (HTML form)
6. User submits email and master password
7. Server authenticates with LastPass API, downloads and decrypts the vault
8. Server generates an authorization code, redirects back to the client
9. Client exchanges the code at `POST /oauth/token` with PKCE verifier
10. Server returns a Bearer access token and refresh token
11. Client sends Bearer token in `Authorization` header on MCP requests
12. Auth middleware validates token, injects LastPass session into context

## Session Management

Sessions are stored in memory as `TokenMapping` structs, keyed by Bearer token. Each mapping holds a pointer to a `lastpass.Session` containing the decryption key, session ID, CSRF token, and decrypted vault entries.

Key behaviors:
- The `lastpass_login` tool can update the session associated with the current token
- The `lastpass_logout` tool invalidates the token mapping
- Refresh tokens generate a new Bearer token pointing to the same session
- The `DecryptionKey` field in `Session` has no JSON tag to prevent accidental serialization
- Background cleanup removes expired states and codes (10 minute TTL) but tokens persist until logout

## Request Lifecycle

1. HTTP request arrives at `/mcp` or `/mcp/`
2. `authMiddleware` extracts Bearer token from `Authorization` header
3. If no token: returns 401 with `WWW-Authenticate` header pointing to resource metadata
4. Token validated via `OAuth2Server.ValidateAccessToken` (looks up in memory map)
5. If invalid: returns 401 with `invalid_token` error
6. LastPass session and Bearer token injected into request context
7. Request forwarded to MCP StreamableHTTP handler
8. MCP SDK routes to the appropriate tool handler
9. Tool handler retrieves session from context, performs vault operation
10. Response returned as JSON through MCP protocol
