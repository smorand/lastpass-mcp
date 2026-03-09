# LastPass Protocol

## API Base URL

All API requests target `https://lastpass.com`.

## API Endpoints

### GET /iterations.php
Returns the PBKDF2 iteration count for a given email.

**Parameters:** `email` (query string)
**Response:** Plain text integer (e.g., `100100`)

### POST /login.php
Authenticates with the derived login hash.

**Form parameters:**
- `method=cli`
- `xml=1`
- `username=<email>`
- `hash=<login_hash>`
- `iterations=<count>`
- `includeprivatekeyenc=1`
- `outofbandsupported=0`

**Response:** XML with either `<ok sessionid="..." token="..."/>` or `<error message="..." cause="..."/>`.

### GET /getaccts.php
Downloads the encrypted vault blob.

**Parameters:** `mobile=1&b64=1&hash=0.0&hasplugin=3.0.23&requestsrc=cli`
**Authentication:** `PHPSESSID` cookie set to the session ID
**Response:** Base64 encoded binary vault blob

### POST /show_website.php
Creates or updates a vault entry.

**Form parameters:**
- `method=cli`
- `token=<csrf_token>` (from login response)
- `aid=<entry_id>` (use `0` for create)
- `url=<url>` (plain text, not encrypted)
- `name=<base64(encrypted_name)>`
- `username=<base64(encrypted_username)>`
- `password=<base64(encrypted_password)>`
- `extra=<base64(encrypted_notes)>`
- `grouping=<base64(encrypted_group)>`

**Authentication:** `PHPSESSID` cookie

### POST /logout.php
Terminates the session.

**Form parameters:** `method=cli`, `noredirect=1`, `token=<csrf_token>`
**Authentication:** `PHPSESSID` cookie

## PBKDF2 Key Derivation

Two values are derived from the user's credentials:

### Decryption Key (32 bytes)
Used to decrypt vault fields.

```
key = PBKDF2_SHA256(password, email, iterations, 32)
```

### Login Hash (hex string)
Used to authenticate with the API. Never sent the raw key.

```
login_hash = hex(PBKDF2_SHA256(key, password, 1, 32))
```

The iteration count is fetched per user from `/iterations.php`. Typical values are 100100 or 600100.

## AES 256 Encryption

### CBC Mode (current standard)
Used for most vault fields and for encrypting new entries.

**Decryption:** Field format is `!<base64_iv>|<base64_ciphertext>`. The `!` prefix and `|` separator distinguish CBC from ECB. IV is 16 bytes. PKCS7 padding is applied.

**Encryption:** A random 16 byte IV is generated. The plaintext is PKCS7 padded, encrypted with AES 256 CBC, and the result is `IV || ciphertext`.

### ECB Mode (legacy)
Some older vault fields use ECB. The field is plain base64 without the `!` prefix. Each 16 byte block is decrypted independently. PKCS7 padding is removed.

The `DecryptField` function auto detects the mode by checking for the `!` prefix.

## Vault Blob Format

The vault blob is a sequence of binary chunks:

```
[4 bytes: ASCII tag][4 bytes: big endian size][size bytes: data]
[4 bytes: ASCII tag][4 bytes: big endian size][size bytes: data]
...
```

### Chunk Types

Only the `ACCT` chunk type is currently parsed. Other chunk types (e.g., `SHAR`, `AACT`, `LPAV`) are skipped.

### ACCT Chunk Internal Structure

Each `ACCT` chunk contains sub items using the same tag+size+data format. Fields are identified by their zero based index:

| Index | Field         | Encoding              |
|-------|---------------|-----------------------|
| 0     | ID            | Plain text            |
| 1     | Name          | Encrypted (CBC/ECB)   |
| 2     | Group         | Encrypted (CBC/ECB)   |
| 3     | URL           | Hex encoded           |
| 4     | Notes         | Encrypted (CBC/ECB)   |
| 9     | Username      | Encrypted (CBC/ECB)   |
| 10    | Password      | Encrypted (CBC/ECB)   |
| 24    | NoteType      | Plain text            |
| 33    | LastModified   | Plain text (timestamp)|
| 40    | LastTouch      | Plain text (timestamp)|

## Entry Types

### Password (default)
Standard credential entries. Fields: ID, Name, URL, Username, Password, Notes, Group, LastModified, LastTouch.

### Payment Card
Identified when NoteType is `Credit Card` and URL is `http://sn`. Card details are stored as structured key:value pairs in the Notes field:

```
NoteType:Credit Card
Name on Card:John Doe
Card Type:Visa
Card Number:4111111111111111
Security Code:123
Start Date:01/2024
Expiration Date:12/2028
```

When creating a payment card entry, the URL is always set to `http://sn` and the Notes field is built from the structured format above.
