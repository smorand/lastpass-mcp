# LastPass Protocol Integration

## Overview

The server communicates directly with the LastPass web API at `https://lastpass.com`. It performs all cryptographic operations locally, replicating the behavior of the official `lastpass-cli` tool.

## API Endpoints

### GET /iterations.php

Returns the PBKDF2 iteration count for a given email address.

| Parameter | Location | Description |
|-----------|----------|-------------|
| `email`   | Query    | User email  |

**Response:** Plain text integer (e.g., `100100`)

### POST /login.php

Authenticates using the derived login hash. Returns an XML response with session credentials or an error.

| Parameter              | Description                          |
|------------------------|--------------------------------------|
| `method`               | Always `cli`                         |
| `xml`                  | Always `2`                           |
| `username`             | User email                           |
| `hash`                 | Login hash (hex encoded)             |
| `iterations`           | Iteration count                      |
| `includeprivatekeyenc` | Always `1`                           |
| `outofbandsupported`   | Always `1`                           |
| `uuid`                 | Trusted device ID (optional)         |

**Success:** `<response><ok sessionid="..." token="..."/></response>`
**Error:** `<response><error message="..." cause="..." retryid="..."/></response>`

### GET /getaccts.php

Downloads the encrypted vault blob.

| Parameter    | Description                     |
|--------------|---------------------------------|
| `mobile`     | Always `1`                      |
| `b64`        | Always `1` (base64 response)    |
| `hash`       | Always `0.0`                    |
| `hasplugin`  | Always `3.0.23`                 |
| `requestsrc` | Always `cli`                    |

**Authentication:** `PHPSESSID` cookie set to the session ID
**Response:** Base64 encoded binary vault blob

### POST /show_website.php

Creates or updates a vault entry. Fields are encrypted before submission.

| Parameter  | Description                                |
|------------|--------------------------------------------|
| `method`   | Always `cli`                               |
| `token`    | CSRF token from login response             |
| `aid`      | Entry ID (`0` for create)                  |
| `url`      | URL (plaintext, not encrypted)             |
| `name`     | Base64(AES encrypted name)                 |
| `username` | Base64(AES encrypted username)             |
| `password` | Base64(AES encrypted password)             |
| `extra`    | Base64(AES encrypted notes)                |
| `grouping` | Base64(AES encrypted group)                |

**Authentication:** `PHPSESSID` cookie

### POST /logout.php

Terminates the session.

| Parameter    | Description          |
|--------------|----------------------|
| `method`     | Always `cli`         |
| `noredirect` | Always `1`           |
| `token`      | CSRF token           |

## Cryptography

### PBKDF2 Key Derivation

Two values are derived from the user's credentials:

**Decryption Key** (32 bytes): Used to decrypt vault fields.
```
key = PBKDF2_SHA256(password, email, iterations, 32)
```

**Login Hash** (hex string): Used to authenticate with the API.
```
login_hash = hex(PBKDF2_SHA256(key, password, 1, 32))
```

The master password and raw key are never transmitted to LastPass. Only the derived login hash is sent.

### AES 256 Encryption

**CBC mode** (current standard): Fields are formatted as `!<base64_IV>|<base64_ciphertext>`. The `!` prefix distinguishes CBC from ECB. A random 16 byte IV is generated for each encryption operation. PKCS7 padding is applied.

**ECB mode** (legacy): Some older vault fields use ECB. The field is plain base64 without the `!` prefix. Each 16 byte block is decrypted independently.

The `DecryptFieldRaw` function tries three formats in order:
1. Raw CBC: `!` (1 byte) + raw IV (16 bytes) + raw ciphertext
2. Raw ECB: raw ciphertext where length is a multiple of 16
3. Base64 fallback: delegates to `DecryptField` for base64 encoded fields

## Vault Blob Format

The vault blob is a sequence of binary chunks:

```
[4 bytes: ASCII tag][4 bytes: big endian size][size bytes: data]
```

Only `ACCT` chunks are parsed. Other chunk types (`SHAR`, `AACT`, `LPAV`, etc.) are skipped.

### ACCT Chunk Fields

Fields within an ACCT chunk use size value format (4 byte big endian size + data, no tag):

| Index | Field          | Encoding            |
|-------|----------------|---------------------|
| 0     | ID             | Plain text          |
| 1     | Name           | Encrypted (CBC/ECB) |
| 2     | Group          | Encrypted (CBC/ECB) |
| 3     | URL            | Hex encoded         |
| 4     | Notes          | Encrypted (CBC/ECB) |
| 7     | Username       | Encrypted (CBC/ECB) |
| 8     | Password       | Encrypted (CBC/ECB) |
| 12    | LastTouch      | Plain text          |
| 29    | NoteType       | Plain text          |
| 31    | LastModified   | Plain text          |

## Out of Band Verification

When LastPass returns an error with a `retryid` attribute, the server enters an OOB polling loop:

1. Wait 3 seconds
2. Resend login request with `outofbandrequest=1`, `outofbandretry=1`, and `outofbandretryid=<id>`
3. If response contains a valid session ID, return success
4. If response contains `cause=outofbandrequired`, update retry ID and continue
5. Timeout after 2 minutes

## Retry Strategy

All API calls use exponential backoff:
- Initial delay: 500ms
- Backoff multiplier: 2x per attempt
- Maximum total duration: 1 minute
- Permanent errors (invalid credentials, rate limiting, unsupported login types) stop immediately
- Context cancellation terminates retries
