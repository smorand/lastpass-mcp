package lastpass

import (
	"crypto/aes"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"testing"
)

// ---------------------------------------------------------------------------
// helpers to construct binary blobs
// ---------------------------------------------------------------------------

// makeChunk builds a single TLV chunk: 4-byte tag + 4-byte big-endian size + data.
func makeChunk(tag string, data []byte) []byte {
	buf := make([]byte, 8+len(data))
	copy(buf[0:4], tag)
	binary.BigEndian.PutUint32(buf[4:8], uint32(len(data)))
	copy(buf[8:], data)
	return buf
}

// makeField builds a sub-item field inside an ACCT chunk (same TLV format).
// The tag value is irrelevant to parsing; only positional index matters.
func makeField(value []byte) []byte {
	return makeChunk("fld\x00", value)
}

// buildMinimalACCT constructs an ACCT chunk payload with the given fields
// placed at their correct positional indices. Missing indices get empty fields.
func buildMinimalACCT(t *testing.T, key []byte, id, name, group, url, notes, username, password, noteType string) []byte {
	t.Helper()

	encryptOrEmpty := func(s string) []byte {
		if s == "" {
			return []byte{}
		}
		ct, err := EncryptAES256CBC([]byte(s), key)
		if err != nil {
			t.Fatalf("encrypt: %v", err)
		}
		iv := ct[:aes.BlockSize]
		ciphertext := ct[aes.BlockSize:]
		field := "!" + base64.StdEncoding.EncodeToString(iv) + "|" + base64.StdEncoding.EncodeToString(ciphertext)
		return []byte(field)
	}

	// We need at least 41 fields (indices 0..40) to cover all parsed positions.
	fields := make([][]byte, 41)
	for i := range fields {
		fields[i] = []byte{}
	}

	fields[0] = []byte(id)
	fields[1] = encryptOrEmpty(name)
	fields[2] = encryptOrEmpty(group)
	fields[3] = []byte(hex.EncodeToString([]byte(url)))
	fields[4] = encryptOrEmpty(notes)
	fields[9] = encryptOrEmpty(username)
	fields[10] = encryptOrEmpty(password)
	fields[24] = []byte(noteType)
	fields[33] = []byte("1700000000")
	fields[40] = []byte("1700000001")

	var acctData []byte
	for _, f := range fields {
		acctData = append(acctData, makeField(f)...)
	}
	return acctData
}

// ---------------------------------------------------------------------------
// ParseVaultBlob
// ---------------------------------------------------------------------------

func TestParseVaultBlob_SinglePasswordEntry(t *testing.T) {
	t.Parallel()

	key := DeriveKey("test@example.com", "test", 100)

	acctPayload := buildMinimalACCT(t, key,
		"12345",         // ID
		"My Website",    // Name
		"Web",           // Group
		"https://a.com", // URL
		"some notes",    // Notes
		"user@a.com",    // Username
		"s3cret",        // Password
		"",              // NoteType (empty = password)
	)

	blob := makeChunk("ACCT", acctPayload)

	entries, err := ParseVaultBlob(blob, key)
	if err != nil {
		t.Fatalf("ParseVaultBlob error: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}

	e := entries[0]
	assertField(t, "ID", e.ID, "12345")
	assertField(t, "Name", e.Name, "My Website")
	assertField(t, "Group", e.Group, "Web")
	assertField(t, "URL", e.URL, "https://a.com")
	assertField(t, "Notes", e.Notes, "some notes")
	assertField(t, "Username", e.Username, "user@a.com")
	assertField(t, "Password", e.Password, "s3cret")
	assertField(t, "Type", e.Type, "password")
	assertField(t, "LastModified", e.LastModified, "1700000000")
	assertField(t, "LastTouch", e.LastTouch, "1700000001")
}

func TestParseVaultBlob_PaymentCard(t *testing.T) {
	t.Parallel()

	key := DeriveKey("test@example.com", "test", 100)

	notes := "NoteType:Credit Card\nName on Card:John Doe\nCard Type:Visa\nCard Number:4111111111111111\nSecurity Code:123\nStart Date:01/2020\nExpiration Date:12/2025"

	acctPayload := buildMinimalACCT(t, key,
		"99999",
		"My Visa",
		"Cards",
		"http://sn", // payment card URL marker
		notes,
		"",
		"",
		"Credit Card", // NoteType triggers payment card detection
	)

	blob := makeChunk("ACCT", acctPayload)

	entries, err := ParseVaultBlob(blob, key)
	if err != nil {
		t.Fatalf("ParseVaultBlob error: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}

	e := entries[0]
	assertField(t, "Type", e.Type, "paymentcard")
	assertField(t, "CardholderName", e.CardholderName, "John Doe")
	assertField(t, "CardType", e.CardType, "Visa")
	assertField(t, "CardNumber", e.CardNumber, "4111111111111111")
	assertField(t, "SecurityCode", e.SecurityCode, "123")
	assertField(t, "StartDate", e.StartDate, "01/2020")
	assertField(t, "ExpirationDate", e.ExpirationDate, "12/2025")
}

func TestParseVaultBlob_MultipleChunks(t *testing.T) {
	t.Parallel()

	key := DeriveKey("test@example.com", "test", 100)

	acct1 := buildMinimalACCT(t, key, "1", "Entry One", "", "https://one.com", "", "u1", "p1", "")
	acct2 := buildMinimalACCT(t, key, "2", "Entry Two", "", "https://two.com", "", "u2", "p2", "")

	// Insert a non-ACCT chunk between them to verify it is skipped.
	var blob []byte
	blob = append(blob, makeChunk("ACCT", acct1)...)
	blob = append(blob, makeChunk("LPAV", []byte("version-data"))...)
	blob = append(blob, makeChunk("ACCT", acct2)...)

	entries, err := ParseVaultBlob(blob, key)
	if err != nil {
		t.Fatalf("ParseVaultBlob error: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}
	assertField(t, "entries[0].ID", entries[0].ID, "1")
	assertField(t, "entries[1].ID", entries[1].ID, "2")
}

func TestParseVaultBlob_Empty(t *testing.T) {
	t.Parallel()

	key := DeriveKey("test@example.com", "test", 100)
	entries, err := ParseVaultBlob([]byte{}, key)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("expected 0 entries, got %d", len(entries))
	}
}

func TestParseVaultBlob_TruncatedChunkSize(t *testing.T) {
	t.Parallel()

	key := DeriveKey("test@example.com", "test", 100)

	// Chunk header says 9999 bytes but blob ends immediately.
	buf := make([]byte, 8)
	copy(buf[0:4], "ACCT")
	binary.BigEndian.PutUint32(buf[4:8], 9999)

	_, err := ParseVaultBlob(buf, key)
	if err == nil {
		t.Fatal("expected error for truncated chunk, got nil")
	}
}

// ---------------------------------------------------------------------------
// Entry type detection
// ---------------------------------------------------------------------------

func TestEntryTypeDetection(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		url      string
		noteType string
		wantType string
	}{
		{
			name:     "regular password",
			url:      "https://github.com",
			noteType: "",
			wantType: "password",
		},
		{
			name:     "payment card",
			url:      "http://sn",
			noteType: "Credit Card",
			wantType: "paymentcard",
		},
		{
			name:     "sn url but not credit card noteType",
			url:      "http://sn",
			noteType: "Server",
			wantType: "password",
		},
	}

	key := DeriveKey("test@example.com", "test", 100)

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			acctPayload := buildMinimalACCT(t, key, "1", "item", "", tc.url, "", "", "", tc.noteType)
			blob := makeChunk("ACCT", acctPayload)
			entries, err := ParseVaultBlob(blob, key)
			if err != nil {
				t.Fatalf("ParseVaultBlob error: %v", err)
			}
			if len(entries) != 1 {
				t.Fatalf("expected 1 entry, got %d", len(entries))
			}
			if entries[0].Type != tc.wantType {
				t.Errorf("Type = %q, want %q", entries[0].Type, tc.wantType)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// parsePaymentCardNotes (vault.go, unexported but tested indirectly above;
// this adds focused table-driven coverage)
// ---------------------------------------------------------------------------

func TestParsePaymentCardFields(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		notes          string
		wantHolder     string
		wantCardType   string
		wantNumber     string
		wantCode       string
		wantStart      string
		wantExpiration string
	}{
		{
			name:           "all fields",
			notes:          "NoteType:Credit Card\nName on Card:Alice\nCard Type:Mastercard\nCard Number:5555555555554444\nSecurity Code:321\nStart Date:06/2021\nExpiration Date:06/2026",
			wantHolder:     "Alice",
			wantCardType:   "Mastercard",
			wantNumber:     "5555555555554444",
			wantCode:       "321",
			wantStart:      "06/2021",
			wantExpiration: "06/2026",
		},
		{
			name:       "partial fields",
			notes:      "NoteType:Credit Card\nName on Card:Bob\nCard Number:1234",
			wantHolder: "Bob",
			wantNumber: "1234",
		},
		{
			name:  "empty notes",
			notes: "",
		},
		{
			name:  "no relevant keys",
			notes: "SomeOtherKey:value\nAnother:thing",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			entry := Entry{Notes: tc.notes}
			parsePaymentCardNotes(&entry)
			assertField(t, "CardholderName", entry.CardholderName, tc.wantHolder)
			assertField(t, "CardType", entry.CardType, tc.wantCardType)
			assertField(t, "CardNumber", entry.CardNumber, tc.wantNumber)
			assertField(t, "SecurityCode", entry.SecurityCode, tc.wantCode)
			assertField(t, "StartDate", entry.StartDate, tc.wantStart)
			assertField(t, "ExpirationDate", entry.ExpirationDate, tc.wantExpiration)
		})
	}
}

// ---------------------------------------------------------------------------
// test helper
// ---------------------------------------------------------------------------

func assertField(t *testing.T, label, got, want string) {
	t.Helper()
	if got != want {
		t.Errorf("%s = %q, want %q", label, got, want)
	}
}
