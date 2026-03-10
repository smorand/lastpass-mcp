# MCP Tools Reference

The server exposes 6 tools via the MCP protocol at `/mcp`.

## lastpass_login

Authenticate to LastPass with email and master password. Creates or refreshes the LastPass session associated with the current Bearer token.

**Input Schema:**
```json
{
  "email": "string (required)",
  "password": "string (required)"
}
```

**Output Schema:**
```json
{
  "success": true,
  "username": "user@example.com",
  "message": "Login successful"
}
```

**Example (already logged in):**
```json
{
  "success": true,
  "username": "user@example.com",
  "message": "Already logged in"
}
```

**Error Responses:**
- `email is required` if email is empty
- `password is required` if password is empty
- `Login failed: <details>` if authentication fails (returned in message field, success=false)

## lastpass_logout

Terminate the current LastPass session and invalidate the Bearer token.

**Input Schema:** None (empty object)

**Output Schema:**
```json
{
  "success": true,
  "message": "Logged out successfully"
}
```

## lastpass_search

Search vault entries by regular expression pattern. Matches against name, url, and username (case insensitive). Optionally filter by entry type.

**Input Schema:**
```json
{
  "pattern": "string (required, regex)",
  "type": "string (optional, 'password' or 'paymentcard')"
}
```

**Output Schema:**
```json
{
  "results": [
    {
      "id": "1234567890",
      "name": "My Site",
      "url": "https://example.com",
      "username": "user@example.com",
      "type": "password"
    }
  ],
  "count": 1
}
```

**Example (filter by type):**
Input: `{"pattern": "visa", "type": "paymentcard"}`
Returns only payment card entries matching "visa".

**Error Responses:**
- `pattern is required` if pattern is empty
- `no active LastPass session` if not logged in
- `invalid regular expression: <details>` if regex is malformed

## lastpass_show

Show full details of a vault entry by ID. Returns all fields including password or payment card details.

**Input Schema:**
```json
{
  "id": "string (required)"
}
```

**Output Schema (password type):**
```json
{
  "id": "1234567890",
  "name": "My Site",
  "url": "https://example.com",
  "username": "user@example.com",
  "password": "s3cret",
  "notes": "Some notes",
  "type": "password",
  "last_modified": "1709913600",
  "last_touch": "1709913600"
}
```

**Output Schema (paymentcard type):**
```json
{
  "id": "9876543210",
  "name": "My Visa",
  "type": "paymentcard",
  "cardholder_name": "John Doe",
  "card_type": "Visa",
  "card_number": "4111111111111111",
  "security_code": "123",
  "start_date": "01/2024",
  "expiration_date": "12/2028",
  "notes": "NoteType:Credit Card\n...",
  "last_modified": "1709913600",
  "last_touch": "1709913600"
}
```

**Error Responses:**
- `id is required` if ID is empty
- `no active LastPass session` if not logged in
- `entry with ID <id> not found` if no entry matches

## lastpass_create

Create a new vault entry. Specify type as 'password' or 'paymentcard' and provide the relevant fields.

**Input Schema:**
```json
{
  "type": "string (required, 'password' or 'paymentcard')",
  "name": "string (required)",
  "url": "string (optional, password type)",
  "username": "string (optional, password type)",
  "password": "string (optional, password type)",
  "notes": "string (optional)",
  "cardholder_name": "string (optional, paymentcard type)",
  "card_type": "string (optional, paymentcard type)",
  "card_number": "string (optional, paymentcard type)",
  "security_code": "string (optional, paymentcard type)",
  "start_date": "string (optional, paymentcard type)",
  "expiration_date": "string (optional, paymentcard type)"
}
```

**Output:** Returns the created entry object with all fields.

**Example (create password):**
```json
{
  "type": "password",
  "name": "New Site",
  "url": "https://newsite.com",
  "username": "admin",
  "password": "p@ssw0rd"
}
```

**Example (create payment card):**
```json
{
  "type": "paymentcard",
  "name": "My Visa",
  "cardholder_name": "John Doe",
  "card_type": "Visa",
  "card_number": "4111111111111111",
  "security_code": "123",
  "expiration_date": "12/2028"
}
```

**Error Responses:**
- `type is required (password or paymentcard)` if type is empty
- `name is required` if name is empty
- `type must be 'password' or 'paymentcard'` if type is invalid
- `no active LastPass session` if not logged in
- `failed to create entry: <details>` if API call fails

## lastpass_update

Update an existing vault entry. Only provided fields are modified; others remain unchanged.

**Input Schema:**
```json
{
  "id": "string (required)",
  "name": "string (optional)",
  "url": "string (optional)",
  "username": "string (optional)",
  "password": "string (optional)",
  "notes": "string (optional)",
  "cardholder_name": "string (optional, paymentcard type)",
  "card_type": "string (optional, paymentcard type)",
  "card_number": "string (optional, paymentcard type)",
  "security_code": "string (optional, paymentcard type)",
  "start_date": "string (optional, paymentcard type)",
  "expiration_date": "string (optional, paymentcard type)"
}
```

**Output:** Returns the updated entry object with all fields.

**Example (update password only):**
```json
{
  "id": "1234567890",
  "password": "newP@ssw0rd!"
}
```

**Error Responses:**
- `id is required` if ID is empty
- `no active LastPass session` if not logged in
- `entry with ID <id> not found` if no entry matches
- `failed to update entry: <details>` if API call fails
