# Vault Management

## Overview

Vault management is the core functionality of the LastPass MCP Server. It exposes six MCP tools that allow AI assistants to interact with the user's LastPass vault through the Model Context Protocol.

## MCP Tools

All tools are available at the `/mcp` endpoint and require a valid OAuth2 Bearer token in the `Authorization` header. The server uses the MCP StreamableHTTP transport (stateful sessions).

### lastpass_login

Authenticates to LastPass and downloads the encrypted vault.

**Input:**
| Field      | Type   | Required | Description                    |
|------------|--------|----------|--------------------------------|
| `email`    | string | Yes      | LastPass account email address |
| `password` | string | Yes      | LastPass master password       |

**Behavior:**
- If already logged in with the same email, returns immediately without re authenticating
- Performs the full login flow: iteration lookup, key derivation, authentication, vault download, decryption
- Stores the session associated with the current Bearer token
- Supports out of band MFA (push/email approval polling)

**Response:**
```json
{"success": true, "username": "user@example.com", "message": "Login successful"}
```

### lastpass_logout

Terminates the current session and invalidates the Bearer token.

**Input:** None (empty object)

**Behavior:**
- Removes the token mapping from the OAuth2 server
- Subsequent requests with the same token return 401

**Response:**
```json
{"success": true, "message": "Logged out successfully"}
```

### lastpass_search

Searches vault entries by regular expression pattern.

**Input:**
| Field     | Type   | Required | Description                                    |
|-----------|--------|----------|------------------------------------------------|
| `pattern` | string | Yes      | Regex pattern (case insensitive)               |
| `type`    | string | No       | Filter by type: `password` or `paymentcard`    |

**Behavior:**
- Matches pattern against entry name, URL, and username
- Rejects overly broad patterns (`.*`, `.+`, `.`, `*`) to prevent accidental full vault dumps
- Returns metadata only (no passwords or card numbers)

**Response:**
```json
{
  "results": [
    {"id": "123", "name": "GitHub", "url": "https://github.com", "username": "user", "type": "password"}
  ],
  "count": 1
}
```

### lastpass_show

Returns full details of a vault entry by ID, including sensitive fields.

**Input:**
| Field | Type   | Required | Description       |
|-------|--------|----------|-------------------|
| `id`  | string | Yes      | LastPass entry ID |

**Behavior:**
- For password entries: returns URL, username, password, notes
- For payment card entries: returns cardholder name, card type, card number, security code, dates
- Includes last_modified and last_touch timestamps

### lastpass_create

Creates a new vault entry.

**Input:**
| Field              | Type   | Required | Applies To  | Description             |
|--------------------|--------|----------|-------------|-------------------------|
| `type`             | string | Yes      | Both        | `password` or `paymentcard` |
| `name`             | string | Yes      | Both        | Entry name              |
| `url`              | string | No       | password    | Site URL                |
| `username`         | string | No       | password    | Login username          |
| `password`         | string | No       | password    | Login password          |
| `notes`            | string | No       | Both        | Free text notes         |
| `cardholder_name`  | string | No       | paymentcard | Name on card            |
| `card_type`        | string | No       | paymentcard | Card network (Visa, etc.) |
| `card_number`      | string | No       | paymentcard | Card number             |
| `security_code`    | string | No       | paymentcard | CVV/CVC                 |
| `start_date`       | string | No       | paymentcard | Card start date         |
| `expiration_date`  | string | No       | paymentcard | Card expiration date    |

**Behavior:**
- Payment card entries automatically set URL to `http://sn` (LastPass sentinel value)
- Payment card details are encoded as structured key:value pairs in the notes field
- All fields are encrypted with AES 256 CBC before being sent to the LastPass API

**Response:**
```json
{"success": true, "id": "1234567890", "message": "Entry 'New Site' created successfully"}
```

### lastpass_update

Updates an existing vault entry. Only provided fields are modified; others remain unchanged.

**Input:**
| Field              | Type   | Required | Description             |
|--------------------|--------|----------|-------------------------|
| `id`               | string | Yes      | Entry ID to update      |
| `name`             | string | No       | New entry name          |
| `url`              | string | No       | New URL                 |
| `username`         | string | No       | New username            |
| `password`         | string | No       | New password            |
| `notes`            | string | No       | New notes               |
| `cardholder_name`  | string | No       | New cardholder name     |
| `card_type`        | string | No       | New card type           |
| `card_number`      | string | No       | New card number         |
| `security_code`    | string | No       | New security code       |
| `start_date`       | string | No       | New start date          |
| `expiration_date`  | string | No       | New expiration date     |

**Behavior:**
- Fetches the current entry from the in memory vault
- Merges provided fields with existing values
- Sends the complete updated entry to the LastPass API

## Entry Types

### Password (default)

Standard credential entries with URL, username, and password fields. The URL is stored in plaintext hex encoding in the vault blob. All other fields are AES 256 encrypted.

### Payment Card

Identified by two conditions:
1. The `NoteType` field (index 29 in the ACCT chunk) equals `Credit Card`
2. The URL equals `http://sn` (LastPass sentinel for secure notes)

Card details are stored as structured text in the Notes field:
```
NoteType:Credit Card
Name on Card:John Doe
Card Type:Visa
Card Number:4111111111111111
Security Code:123
Start Date:01/2024
Expiration Date:12/2028
```

## Vault Refresh

The server provides a `/api/refresh` HTTP endpoint (Bearer token required) that re downloads and re decrypts the vault without requiring a new login. This updates the in memory entries for the session and triggers a state persistence save.

## Error Handling

All tool handlers return structured error messages. Common errors:

| Error                              | Cause                                    |
|------------------------------------|------------------------------------------|
| `email is required`                | Missing email in login request           |
| `no active LastPass session`       | Token has no associated vault session    |
| `entry with ID <id> not found`     | Entry ID does not exist in the vault     |
| `search pattern is too broad`      | Pattern would match all entries          |
| `invalid regular expression`       | Malformed regex in search pattern        |
| `Login failed: <details>`         | LastPass API authentication failure      |

All LastPass API calls use exponential backoff retry (starting at 500ms, doubling per attempt, up to 1 minute total). Permanent errors (invalid credentials, rate limiting) stop retries immediately.
