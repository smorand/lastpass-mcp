# LastPass MCP Server -- Specification Document

> Generated on: 2026-03-09
> Version: 1.0
> Status: Draft

## 1. Executive Summary

LastPass MCP Server is a Go-based MCP (Model Context Protocol) server exposing LastPass vault operations via HTTP Streamable transport. It wraps the `lpass` CLI to provide six MCP tools (login, logout, search, show, create, update) for managing password and payment card entries. The server includes a minimal web UI exclusively for managing LastPass authentication (entering the master password). The master password is stored in a dedicated in-memory secret; when the secret is empty, authentication must be requested before any vault operation can proceed.

The server targets AI agents as primary consumers, enabling them to search, read, create, and update LastPass vault entries programmatically.

## 2. Scope

### 2.1 In Scope
- MCP HTTP Streamable server (Go, using `mcp-go` library)
- Minimal web UI for authentication management only (enter master password, trigger `lpass login`)
- Six MCP tools: `login`, `logout`, `search`, `show`, `create`, `update`
- Support for two entry types: `password` and `paymentcard`
- Regexp-based search across URL, name, and username fields
- Complete entry display with all fields
- Create and update operations for both supported entry types
- In-memory secret storage for the master password
- Authentication state management (logged-in/logged-out detection)

### 2.2 Out of Scope (Non-Goals)
- Folder management (user does not use folders)
- Shared folder operations
- Entry deletion (`rm` command)
- Entry duplication
- Password generation
- Import/export functionality
- Attachment management
- Secure note types other than payment cards
- Multi-factor authentication handling via MCP (MFA must be handled at the CLI level or pre-configured with `--trust`)
- User management or enterprise features

## 3. User Personas & Actors

### AI Agent (Primary)
An LLM-based agent that calls MCP tools to search, read, create, and update credentials stored in LastPass. The agent never sees the master password directly; it triggers login/logout via MCP tools.

### Human Operator (Secondary)
A human who uses the web UI to enter the LastPass master password when authentication is needed. This is the only interaction the human has with the server.

## 4. Usage Scenarios

### SC-001: Initial Authentication via Web UI
**Actor:** Human Operator
**Preconditions:** Server is running. No active LastPass session (secret is empty).
**Flow:**
1. Human navigates to the web UI at `http://<host>:<port>/`.
2. System displays a login form with fields for LastPass email and master password.
3. Human enters email and master password, submits the form.
4. System executes `lpass login --trust <email>` with the provided password piped to stdin.
5. System stores the master password in the in-memory secret.
6. System displays a success message with the logged-in username.
**Postconditions:** `lpass status` returns logged-in. The in-memory secret holds the master password. MCP tools can now operate.
**Exceptions:**
- [EXC-001a]: Invalid credentials --> System displays "Invalid master password or email" error. Secret remains empty.
- [EXC-001b]: Network unreachable (cannot contact LastPass servers) --> System displays "Unable to connect to LastPass servers" error.
- [EXC-001c]: MFA required and not pre-trusted --> System displays "Multi-factor authentication required. Please run `lpass login --trust` manually first."

### SC-002: Agent Searches for Entries
**Actor:** AI Agent
**Preconditions:** Active LastPass session (user is logged in).
**Flow:**
1. Agent calls `search` tool with a regexp pattern and optionally a type filter (`password` or `paymentcard`).
2. System executes `lpass ls` to get the full entry list, then applies the regexp pattern against name, URL, and username of each entry.
3. System returns a JSON array of matching entries with: id, name, username, url, and type.
**Postconditions:** No state change. Agent receives search results.
**Exceptions:**
- [EXC-002a]: No active session --> System returns an error: "Not logged in. Authentication required."
- [EXC-002b]: Invalid regexp --> System returns an error: "Invalid regular expression: <details>."
- [EXC-002c]: No matches found --> System returns an empty array (not an error).

### SC-003: Agent Shows Entry Details
**Actor:** AI Agent
**Preconditions:** Active LastPass session. Agent knows the entry ID (from a prior search).
**Flow:**
1. Agent calls `show` tool with the entry ID.
2. System executes `lpass show --json <id>`.
3. System parses the JSON output and returns the complete entry: id, name, url, username, password, notes, and any additional fields (for payment cards: cardholder name, card number, security code, start date, expiration date, type).
**Postconditions:** No state change.
**Exceptions:**
- [EXC-003a]: No active session --> Error: "Not logged in. Authentication required."
- [EXC-003b]: Entry not found --> Error: "Entry with ID <id> not found."

### SC-004: Agent Creates a New Entry
**Actor:** AI Agent
**Preconditions:** Active LastPass session.
**Flow:**
1. Agent calls `create` tool with entry data. For `password` type: name, url, username, password, notes. For `paymentcard` type: name, cardholder name, card type, card number, security code, start date, expiration date, notes.
2. System validates all required fields are present.
3. For `password` type: System pipes the data to `lpass add <name> --non-interactive`.
4. For `paymentcard` type: System creates a secure note with `--note-type=credit-card` and populates the appropriate fields.
5. System returns the newly created entry ID.
**Postconditions:** New entry exists in the LastPass vault. Local cache is updated.
**Exceptions:**
- [EXC-004a]: No active session --> Error: "Not logged in. Authentication required."
- [EXC-004b]: Missing required fields --> Error: "Missing required field: <field_name>."
- [EXC-004c]: Duplicate name exists --> The entry is created anyway (LastPass allows duplicate names).
- [EXC-004d]: Sync failure --> Error: "Failed to sync with LastPass servers."

### SC-005: Agent Updates an Existing Entry
**Actor:** AI Agent
**Preconditions:** Active LastPass session. Agent knows the entry ID.
**Flow:**
1. Agent calls `update` tool with the entry ID and fields to update. Only provided fields are modified; others remain unchanged.
2. System first reads the current entry via `lpass show --json <id>` to get existing values.
3. System merges the provided fields with existing values.
4. System writes the updated entry via `lpass edit <id> --non-interactive`.
5. System returns the updated entry.
**Postconditions:** Entry is updated in the vault.
**Exceptions:**
- [EXC-005a]: No active session --> Error: "Not logged in. Authentication required."
- [EXC-005b]: Entry not found --> Error: "Entry with ID <id> not found."
- [EXC-005c]: Sync failure --> Error: "Failed to sync with LastPass servers."

### SC-006: Agent Logs Out
**Actor:** AI Agent
**Preconditions:** Active LastPass session.
**Flow:**
1. Agent calls `logout` tool.
2. System executes `lpass logout --force`.
3. System clears the in-memory secret (sets it to empty).
4. System returns confirmation.
**Postconditions:** No active session. Secret is empty. All subsequent tool calls (except login) will require re-authentication.
**Exceptions:**
- [EXC-006a]: Already logged out --> System clears the secret anyway and returns success (idempotent).

### SC-007: Agent Calls Tool While Not Authenticated
**Actor:** AI Agent
**Preconditions:** No active LastPass session (secret is empty).
**Flow:**
1. Agent calls any tool other than `login`.
2. System checks `lpass status` and detects no active session.
3. System returns error: "Not logged in. Authentication required."
**Postconditions:** No state change.

### SC-008: Agent Triggers Login via MCP Tool
**Actor:** AI Agent
**Preconditions:** No active LastPass session.
**Flow:**
1. Agent calls `login` tool with email and master password.
2. System executes `lpass login --trust <email>` with password piped to stdin.
3. System stores the master password in the in-memory secret.
4. System returns success with logged-in username.
**Postconditions:** Active session established.
**Exceptions:**
- [EXC-008a]: Invalid credentials --> Error with details from lpass CLI.
- [EXC-008b]: Already logged in --> System returns success without re-authenticating (idempotent).

## 5. Functional Requirements

### FR-001: MCP HTTP Streamable Server
- **Description:** The server must implement MCP protocol over HTTP Streamable transport.
- **Inputs:** HTTP requests conforming to MCP protocol.
- **Outputs:** MCP-compliant HTTP responses.
- **Business Rules:** Must use `mcp-go` library. Single binary. Configuration via YAML file with `--config` flag and CLI overrides.
- **Priority:** Must-have

### FR-002: In-Memory Secret Storage
- **Description:** The server must maintain the LastPass master password in an in-memory secret. The secret must never be written to disk.
- **Inputs:** Master password provided via login tool or web UI.
- **Outputs:** N/A (internal state).
- **Business Rules:** Secret is cleared on logout. Secret is empty on server startup. When secret is empty, all vault operations must fail with "authentication required."
- **Priority:** Must-have

### FR-003: Authentication State Detection
- **Description:** Before every vault operation, the system must verify authentication state by running `lpass status`.
- **Inputs:** None.
- **Outputs:** Boolean indicating logged-in status.
- **Business Rules:** If `lpass status` returns non-zero exit code or does not indicate a logged-in user, the operation must be rejected. The system must also verify the in-memory secret is non-empty.
- **Priority:** Must-have

### FR-004: Login Tool
- **Description:** MCP tool that authenticates to LastPass.
- **Inputs:** `email` (string, required), `password` (string, required).
- **Outputs:** JSON object with `success` (bool) and `username` (string).
- **Business Rules:** Executes `lpass login --trust <email>` with password on stdin. Stores password in secret on success. Uses `--trust` to avoid repeated MFA prompts. If already logged in as the same user, returns success without re-authenticating.
- **Priority:** Must-have

### FR-005: Logout Tool
- **Description:** MCP tool that terminates the LastPass session.
- **Inputs:** None.
- **Outputs:** JSON object with `success` (bool).
- **Business Rules:** Executes `lpass logout --force`. Clears the in-memory secret. Idempotent (succeeds even if already logged out).
- **Priority:** Must-have

### FR-006: Search Tool
- **Description:** MCP tool that searches vault entries by regexp.
- **Inputs:** `pattern` (string, required, a regular expression), `type` (string, optional, one of `password` or `paymentcard`).
- **Outputs:** JSON array of matching entries. Each entry contains: `id`, `name`, `url`, `username`, `type`.
- **Business Rules:** The regexp is matched case-insensitively against three fields: name, URL, and username. Uses `lpass show --basic-regexp --json --expand-multi <pattern>` to get results. If `type` is specified, results are filtered to only that entry type. Payment card entries are identified by having URL `http://sn` and a `NoteType` of `Credit Card` in their notes. Password entries are everything else (entries with a non-`http://sn` URL).
- **Priority:** Must-have

### FR-007: Show Tool
- **Description:** MCP tool that displays full entry details.
- **Inputs:** `id` (string, required, the LastPass entry ID).
- **Outputs:** JSON object with all entry fields. For password type: `id`, `name`, `url`, `username`, `password`, `notes`, `type` ("password"), `last_modified`, `last_touch`. For paymentcard type: `id`, `name`, `type` ("paymentcard"), `cardholder_name`, `card_type`, `card_number`, `security_code`, `start_date`, `expiration_date`, `notes`, `last_modified`, `last_touch`.
- **Business Rules:** Uses `lpass show --json <id>`. Parses secure note fields for payment card entries.
- **Priority:** Must-have

### FR-008: Create Tool
- **Description:** MCP tool that creates a new vault entry.
- **Inputs:** `type` (string, required, `password` or `paymentcard`). For `password`: `name` (required), `url` (optional, defaults to ""), `username` (optional, defaults to ""), `password` (optional, defaults to ""), `notes` (optional, defaults to ""). For `paymentcard`: `name` (required), `cardholder_name` (optional), `card_type` (optional), `card_number` (optional), `security_code` (optional), `start_date` (optional), `expiration_date` (optional), `notes` (optional).
- **Outputs:** JSON object with the created entry (same format as show).
- **Business Rules:** For password type, uses `lpass add <name> --non-interactive` with data piped to stdin. For paymentcard type, uses `lpass add <name> --note-type=credit-card --non-interactive`. After creation, retrieves the entry to return its ID and full data.
- **Priority:** Must-have

### FR-009: Update Tool
- **Description:** MCP tool that updates an existing vault entry.
- **Inputs:** `id` (string, required). Plus any subset of the fields accepted by create (depending on type). Only provided fields are updated.
- **Outputs:** JSON object with the updated entry (same format as show).
- **Business Rules:** First reads the current entry, merges provided fields, then writes back via `lpass edit <id> --non-interactive`. For payment card entries, individual secure note fields are updated via `lpass edit <id> --field=<fieldname> --non-interactive`.
- **Priority:** Must-have

### FR-010: Web UI for Authentication
- **Description:** A minimal web interface served at the root path (`/`) for managing LastPass authentication.
- **Inputs:** HTTP GET for the page, HTTP POST for login/logout actions.
- **Outputs:** HTML page with login form or logged-in status.
- **Business Rules:** The web UI must display: (a) a login form when not authenticated (email + password fields), (b) the currently logged-in user and a logout button when authenticated. No other vault operations are exposed via the web UI. The web UI must be a single HTML page (embedded in the Go binary). No external CSS/JS dependencies.
- **Priority:** Must-have

### FR-011: CLI Wrapper Layer
- **Description:** All LastPass operations must be performed by shelling out to the `lpass` CLI binary.
- **Inputs:** CLI commands and arguments.
- **Outputs:** Parsed stdout/stderr from the CLI.
- **Business Rules:** The `lpass` binary path must be configurable (default: `lpass` on PATH). The `LPASS_AGENT_TIMEOUT=0` environment variable must be set to keep the agent alive indefinitely. Stdin piping must be used for non-interactive operations. The `LPASS_DISABLE_PINENTRY=1` environment variable must be set to prevent GUI password prompts.
- **Priority:** Must-have

### FR-012: Entry Type Detection
- **Description:** The system must reliably distinguish between password and payment card entries.
- **Inputs:** Entry data from `lpass show --json`.
- **Outputs:** Entry type string: `password` or `paymentcard`.
- **Business Rules:** An entry is a `paymentcard` if its URL is `http://sn` and its notes contain `NoteType:Credit Card`. All other entries are `password` type.
- **Priority:** Must-have

## 6. Non-Functional Requirements

### 6.1 Performance
- Tool response time must be under 10 seconds for search, show, create, and update operations (bound by lpass CLI performance).
- Login may take up to 30 seconds due to KDF iterations and network latency.
- The server must handle sequential MCP requests (concurrent vault operations are not required, as `lpass` CLI uses file-based locking).

### 6.2 Security
- The master password must never be logged, traced, or written to disk.
- The in-memory secret must be cleared on logout and on server shutdown.
- The web UI must only be accessible on localhost by default (configurable bind address).
- No authentication is required for the web UI or MCP endpoint (the server is expected to run locally or behind a reverse proxy that handles access control).
- The `LPASS_DISABLE_PINENTRY=1` environment variable must be set to prevent the CLI from spawning GUI prompts.

### 6.3 Usability
- The web UI must be functional without JavaScript (pure HTML form submission).
- Error messages must be clear and actionable.

### 6.4 Reliability
- The server must detect stale sessions (e.g., `lpass` agent timeout) and report "authentication required" rather than producing cryptic errors.
- If the `lpass` binary is not found on startup, the server must exit with a clear error message.

### 6.5 Observability
- **Collector**: JSONL file (default)
- **Trace file path**: `traces/lastpass-mcp.jsonl`
- **What to trace**: MCP tool calls (INFO), lpass CLI executions with arguments but NOT passwords (INFO), authentication state changes (INFO), errors (ERROR), web UI requests (DEBUG)
- **Sensitive data exclusion**: Master password, entry passwords, card numbers, security codes must NEVER appear in traces or logs
- Structured logging via `slog` with JSON format

### 6.6 Deployment
- Single Go binary
- Docker support with `lpass` CLI pre-installed
- Configuration via YAML file (`--config` flag)
- Configurable bind address and port (default: `localhost:8080`)

### 6.7 Scalability
- Single-instance deployment only. No horizontal scaling required (the `lpass` CLI maintains local state per user).

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

### In-Memory Secret
| Field | Type | Description |
|-------|------|-------------|
| email | string | LastPass account email |
| password | string | Master password (cleared on logout) |

### Configuration (YAML)
| Field | Type | Default | Description |
|-------|------|---------|-------------|
| bind_address | string | "localhost:8080" | Server listen address |
| lpass_path | string | "lpass" | Path to lpass binary |
| log_level | string | "info" | Logging level |
| trace_file | string | "traces/lastpass-mcp.jsonl" | OpenTelemetry trace output path |

## 8. Documentation Requirements

All documentation listed below must be created and maintained as part of this project.

### 8.1 README.md
- Project description, purpose, and audience
- Prerequisites (Go, lpass CLI installation)
- How to build, configure, and run the server
- Configuration reference (YAML fields, CLI flags)
- MCP tool reference with example calls
- Docker usage instructions

### 8.2 CLAUDE.md & .agent_docs/
- `CLAUDE.md`: Compact index with project overview, key commands, essential conventions, and documentation index referencing `.agent_docs/` files
- `.agent_docs/mcp-tools.md`: Detailed MCP tool specifications with input/output schemas
- `.agent_docs/architecture.md`: Server architecture, CLI wrapper design, secret management

### 8.3 docs/*
- `docs/setup.md`: Detailed setup guide including lpass CLI installation on various platforms
- `docs/configuration.md`: Full configuration reference

## 9. Traceability Matrix

| Scenario | Functional Req | E2E Tests (Happy) | E2E Tests (Failure) | E2E Tests (Edge) |
|----------|---------------|-------------------|---------------------|-------------------|
| SC-001 | FR-004, FR-010, FR-002 | E2E-001 | E2E-002, E2E-003, E2E-004 | E2E-005 |
| SC-002 | FR-006, FR-003, FR-012 | E2E-010, E2E-011 | E2E-012, E2E-013 | E2E-014, E2E-015, E2E-016 |
| SC-003 | FR-007, FR-003, FR-012 | E2E-020, E2E-021 | E2E-022, E2E-023 | E2E-024 |
| SC-004 | FR-008, FR-003, FR-012 | E2E-030, E2E-031 | E2E-032, E2E-033, E2E-034 | E2E-035, E2E-036 |
| SC-005 | FR-009, FR-003, FR-012 | E2E-040, E2E-041 | E2E-042, E2E-043, E2E-044 | E2E-045, E2E-046 |
| SC-006 | FR-005, FR-002 | E2E-050 | E2E-051 | E2E-052 |
| SC-007 | FR-003, FR-002 | N/A | E2E-060 | N/A |
| SC-008 | FR-004, FR-002 | E2E-070 | E2E-071, E2E-072 | E2E-073 |

## 10. End-to-End Test Suite

All tests must be implemented in the `tests/` directory. Each feature must have tests covering happy paths, failure paths, edge cases, and error recovery.

### 10.1 Test Summary

| Test ID | Category | Scenario | FR refs | Priority |
|---------|----------|----------|---------|----------|
| E2E-001 | Core Journey | SC-001 | FR-004, FR-010 | Critical |
| E2E-002 | Error | SC-001 | FR-004, FR-010 | Critical |
| E2E-003 | Error | SC-001 | FR-004, FR-010 | High |
| E2E-004 | Error | SC-001 | FR-004, FR-010 | Medium |
| E2E-005 | Edge | SC-001 | FR-004, FR-010 | Medium |
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
| E2E-070 | Core Journey | SC-008 | FR-004, FR-002 | Critical |
| E2E-071 | Error | SC-008 | FR-004 | Critical |
| E2E-072 | Error | SC-008 | FR-004 | High |
| E2E-073 | Edge | SC-008 | FR-004, FR-002 | Medium |

### 10.2 Test Specifications

#### E2E-001: Web UI Login Success
- **Category:** Core Journey
- **Scenario:** SC-001 -- Initial authentication via web UI
- **Requirements:** FR-004, FR-010
- **Preconditions:** Server running. No active LastPass session.
- **Steps:**
  - Given the server is running and no user is logged in
  - When the human navigates to `GET /` in a browser
  - Then a login form with email and password fields is displayed
  - When the human submits valid email and master password
  - Then the page displays "Logged in as <email>"
  - And `lpass status` confirms an active session
- **Priority:** Critical

#### E2E-002: Web UI Login with Invalid Credentials
- **Category:** Error
- **Scenario:** SC-001
- **Requirements:** FR-004, FR-010
- **Preconditions:** Server running. No active LastPass session.
- **Steps:**
  - Given the server is running and no user is logged in
  - When the human submits an invalid email or wrong master password via the web UI
  - Then the page displays an error message containing "Invalid" or the lpass error text
  - And `lpass status` confirms no active session
  - And the in-memory secret remains empty
- **Priority:** Critical

#### E2E-003: Web UI Login with Network Failure
- **Category:** Error
- **Scenario:** SC-001
- **Requirements:** FR-004, FR-010
- **Preconditions:** Server running. LastPass servers unreachable.
- **Steps:**
  - Given the server is running and LastPass servers are unreachable
  - When the human submits credentials via the web UI
  - Then the page displays an error about connectivity
  - And the in-memory secret remains empty
- **Priority:** High

#### E2E-004: Web UI Login when MFA Required
- **Category:** Error
- **Scenario:** SC-001
- **Requirements:** FR-004, FR-010
- **Preconditions:** Server running. Account requires MFA and device is not trusted.
- **Steps:**
  - Given the account requires MFA and `--trust` has not been established
  - When the human submits valid credentials via the web UI
  - Then the page displays an error about MFA being required
- **Priority:** Medium

#### E2E-005: Web UI Shows Logged-In State on Reload
- **Category:** Edge
- **Scenario:** SC-001
- **Requirements:** FR-004, FR-010
- **Preconditions:** User is logged in via web UI.
- **Steps:**
  - Given a user is already logged in
  - When the human navigates to `GET /`
  - Then the page displays the logged-in username and a logout button (not a login form)
- **Priority:** Medium

#### E2E-010: Search Passwords by Regexp
- **Category:** Core Journey
- **Scenario:** SC-002 -- Agent searches for entries
- **Requirements:** FR-006, FR-012
- **Preconditions:** Active session. Vault contains entries matching the pattern.
- **Steps:**
  - Given the user is logged in and the vault contains entries with "github" in the name
  - When the agent calls `search` with pattern `github.*`
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

#### E2E-012: Search While Not Logged In
- **Category:** Error
- **Scenario:** SC-002
- **Requirements:** FR-006, FR-003
- **Preconditions:** No active session.
- **Steps:**
  - Given no user is logged in
  - When the agent calls `search` with any pattern
  - Then the response is an error: "Not logged in. Authentication required."
- **Priority:** Critical

#### E2E-013: Search with Invalid Regexp
- **Category:** Error
- **Scenario:** SC-002
- **Requirements:** FR-006
- **Preconditions:** Active session.
- **Steps:**
  - Given the user is logged in
  - When the agent calls `search` with pattern `[invalid`
  - Then the response is an error containing "Invalid regular expression"
- **Priority:** High

#### E2E-014: Search Returns Empty Results
- **Category:** Edge
- **Scenario:** SC-002
- **Requirements:** FR-006
- **Preconditions:** Active session.
- **Steps:**
  - Given the user is logged in
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
- **Preconditions:** Active session. Entry with known ID exists.
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

#### E2E-022: Show While Not Logged In
- **Category:** Error
- **Scenario:** SC-003
- **Requirements:** FR-007, FR-003
- **Preconditions:** No active session.
- **Steps:**
  - Given no user is logged in
  - When the agent calls `show` with any ID
  - Then the response is an error: "Not logged in. Authentication required."
- **Priority:** Critical

#### E2E-023: Show Non-Existent Entry
- **Category:** Error
- **Scenario:** SC-003
- **Requirements:** FR-007
- **Preconditions:** Active session.
- **Steps:**
  - Given the user is logged in
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
- **Preconditions:** Active session.
- **Steps:**
  - Given the user is logged in
  - When the agent calls `create` with type "password", name "TestSite", url "https://test.com", username "user@test.com", password "s3cret!", notes "test notes"
  - Then the response contains the created entry with a non-zero id
  - And `lpass show` confirms the entry exists with all provided fields
- **Priority:** Critical

#### E2E-031: Create Payment Card Entry
- **Category:** Feature
- **Scenario:** SC-004
- **Requirements:** FR-008, FR-012
- **Preconditions:** Active session.
- **Steps:**
  - Given the user is logged in
  - When the agent calls `create` with type "paymentcard", name "My Visa", cardholder_name "John Doe", card_type "Visa", card_number "4111111111111111", security_code "123", expiration_date "2028-12"
  - Then the response contains the created entry with type "paymentcard"
  - And `lpass show` confirms the entry exists as a Credit Card secure note
- **Priority:** Critical

#### E2E-032: Create While Not Logged In
- **Category:** Error
- **Scenario:** SC-004
- **Requirements:** FR-008, FR-003
- **Preconditions:** No active session.
- **Steps:**
  - Given no user is logged in
  - When the agent calls `create` with any data
  - Then the response is an error: "Not logged in. Authentication required."
- **Priority:** Critical

#### E2E-033: Create with Missing Required Field (Name)
- **Category:** Error
- **Scenario:** SC-004
- **Requirements:** FR-008
- **Preconditions:** Active session.
- **Steps:**
  - Given the user is logged in
  - When the agent calls `create` with type "password" but no name
  - Then the response is an error: "Missing required field: name."
- **Priority:** High

#### E2E-034: Create with Invalid Type
- **Category:** Error
- **Scenario:** SC-004
- **Requirements:** FR-008
- **Preconditions:** Active session.
- **Steps:**
  - Given the user is logged in
  - When the agent calls `create` with type "securenote"
  - Then the response is an error indicating invalid type (must be "password" or "paymentcard")
- **Priority:** High

#### E2E-035: Create Entry with Empty Optional Fields
- **Category:** Edge
- **Scenario:** SC-004
- **Requirements:** FR-008
- **Preconditions:** Active session.
- **Steps:**
  - Given the user is logged in
  - When the agent calls `create` with type "password" and name "MinimalEntry" only
  - Then the entry is created successfully with empty url, username, password, and notes
- **Priority:** Medium

#### E2E-036: Create Entry with Very Long Notes
- **Category:** Edge
- **Scenario:** SC-004
- **Requirements:** FR-008
- **Preconditions:** Active session.
- **Steps:**
  - Given the user is logged in
  - When the agent calls `create` with notes of 40,000 characters
  - Then the entry is created successfully (lpass max note length is 45,000)
- **Priority:** Medium

#### E2E-040: Update Password Entry
- **Category:** Core Journey
- **Scenario:** SC-005 -- Agent updates an existing entry
- **Requirements:** FR-009, FR-012
- **Preconditions:** Active session. An existing password entry with known ID.
- **Steps:**
  - Given a password entry exists with id "12345"
  - When the agent calls `update` with id "12345" and password "newP@ss!"
  - Then the response contains the updated entry with the new password
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

#### E2E-042: Update While Not Logged In
- **Category:** Error
- **Scenario:** SC-005
- **Requirements:** FR-009, FR-003
- **Preconditions:** No active session.
- **Steps:**
  - Given no user is logged in
  - When the agent calls `update` with any data
  - Then the response is an error: "Not logged in. Authentication required."
- **Priority:** Critical

#### E2E-043: Update Non-Existent Entry
- **Category:** Error
- **Scenario:** SC-005
- **Requirements:** FR-009
- **Preconditions:** Active session.
- **Steps:**
  - Given the user is logged in
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
- **Preconditions:** Active session.
- **Steps:**
  - Given the user is logged in
  - When the agent calls `logout`
  - Then the response indicates success
  - And `lpass status` confirms no active session
  - And the in-memory secret is empty
- **Priority:** Critical

#### E2E-051: Logout When lpass CLI Fails
- **Category:** Error
- **Scenario:** SC-006
- **Requirements:** FR-005
- **Preconditions:** Active session. `lpass` binary is temporarily unavailable.
- **Steps:**
  - Given the user is logged in but the lpass binary is not accessible
  - When the agent calls `logout`
  - Then the response is an error about CLI failure
  - But the in-memory secret is still cleared (defensive)
- **Priority:** Medium

#### E2E-052: Logout When Already Logged Out (Idempotent)
- **Category:** Edge
- **Scenario:** SC-006
- **Requirements:** FR-005, FR-002
- **Preconditions:** No active session.
- **Steps:**
  - Given no user is logged in
  - When the agent calls `logout`
  - Then the response indicates success (idempotent)
  - And the in-memory secret remains empty
- **Priority:** Medium

#### E2E-060: Any Tool Call While Not Authenticated
- **Category:** Error
- **Scenario:** SC-007 -- Agent calls tool while not authenticated
- **Requirements:** FR-003, FR-002
- **Preconditions:** No active session.
- **Steps:**
  - Given no user is logged in
  - When the agent calls `search`, `show`, `create`, or `update`
  - Then each call returns error: "Not logged in. Authentication required."
- **Priority:** Critical

#### E2E-070: Login via MCP Tool
- **Category:** Core Journey
- **Scenario:** SC-008 -- Agent triggers login via MCP tool
- **Requirements:** FR-004, FR-002
- **Preconditions:** No active session.
- **Steps:**
  - Given no user is logged in
  - When the agent calls `login` with valid email and password
  - Then the response contains success:true and the username
  - And `lpass status` confirms active session
  - And the in-memory secret holds the password
- **Priority:** Critical

#### E2E-071: Login via MCP Tool with Invalid Credentials
- **Category:** Error
- **Scenario:** SC-008
- **Requirements:** FR-004
- **Preconditions:** No active session.
- **Steps:**
  - Given no user is logged in
  - When the agent calls `login` with invalid credentials
  - Then the response contains success:false and an error message
  - And the in-memory secret remains empty
- **Priority:** Critical

#### E2E-072: Login via MCP Tool with Missing Fields
- **Category:** Error
- **Scenario:** SC-008
- **Requirements:** FR-004
- **Preconditions:** No active session.
- **Steps:**
  - Given no user is logged in
  - When the agent calls `login` without email or password
  - Then the response is an error: "Missing required field: email" or "Missing required field: password"
- **Priority:** High

#### E2E-073: Login via MCP Tool When Already Logged In
- **Category:** Edge
- **Scenario:** SC-008
- **Requirements:** FR-004, FR-002
- **Preconditions:** Active session.
- **Steps:**
  - Given the user is already logged in as "user@example.com"
  - When the agent calls `login` with the same email
  - Then the response indicates success without re-authenticating
- **Priority:** Medium

## 11. Open Questions & TBDs

- **TBD-001:** How should the server handle `lpass` agent timeouts? The specification sets `LPASS_AGENT_TIMEOUT=0` (never timeout), but if the agent dies unexpectedly, the server must detect this via `lpass status` and request re-authentication.
- **TBD-002:** Should the web UI support HTTPS (TLS termination)? Currently specified as HTTP-only with localhost binding. For remote access, a reverse proxy would handle TLS.
- **TBD-003:** LastPass MFA handling: the spec uses `--trust` to avoid MFA after first login. If the trust is not established, the MCP login tool cannot handle interactive MFA. Should we document a manual first-login procedure?
- **TBD-004:** Rate limiting: LastPass may rate-limit API calls. Should the server implement backoff/retry logic for CLI commands that fail due to rate limiting?

## 12. Glossary

| Term | Definition |
|------|-----------|
| MCP | Model Context Protocol, a standard for AI agent tool communication |
| HTTP Streamable | MCP transport over standard HTTP with streaming support |
| lpass | The LastPass CLI binary (`lastpass-cli` package) |
| Vault | The encrypted LastPass password store |
| Secure Note | A LastPass entry type for structured data (used for payment cards) |
| KDF | Key Derivation Function, used by LastPass to derive encryption keys from the master password |
| In-memory secret | A server-side variable holding the master password, never persisted to disk |
| mcp-go | Go library implementing MCP server protocol |
| Entry | A single record in the LastPass vault (password or payment card) |
