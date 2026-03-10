package lastpass

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log/slog"
	"strings"
)

// Entry represents a single item stored in the LastPass vault.
type Entry struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	URL          string `json:"url"`
	Username     string `json:"username"`
	Password     string `json:"password"`
	Notes        string `json:"notes"`
	Type         string `json:"type"` // "password" or "paymentcard"
	Group        string `json:"group"`
	LastModified string `json:"last_modified"`
	LastTouch    string `json:"last_touch"`

	// Payment card specific fields (populated when Type is "paymentcard")
	CardholderName string `json:"cardholder_name,omitempty"`
	CardType       string `json:"card_type,omitempty"`
	CardNumber     string `json:"card_number,omitempty"`
	SecurityCode   string `json:"security_code,omitempty"`
	StartDate      string `json:"start_date,omitempty"`
	ExpirationDate string `json:"expiration_date,omitempty"`
}

// ParseVaultBlob parses the binary vault blob and decrypts all account entries
// using the provided encryption key. The blob consists of a sequence of chunks,
// each with a 4-byte ASCII tag, a 4-byte big-endian size, and then the data.
func ParseVaultBlob(blob []byte, key []byte) ([]Entry, error) {
	var entries []Entry
	pos := 0

	for pos < len(blob) {
		if pos+8 > len(blob) {
			break
		}

		tag := string(blob[pos : pos+4])
		size := int(binary.BigEndian.Uint32(blob[pos+4 : pos+8]))
		pos += 8

		if pos+size > len(blob) {
			return nil, fmt.Errorf("chunk %q at offset %d: size %d exceeds blob length", tag, pos-8, size)
		}

		data := blob[pos : pos+size]
		pos += size

		if tag == "ACCT" {
			entry, err := parseAccountChunk(data, key)
			if err != nil {
				slog.Warn("skipping account entry due to parse error", "error", err)
				continue
			}
			entries = append(entries, entry)
		}
	}

	return entries, nil
}

// parseAccountChunk parses a single ACCT chunk into an Entry.
// Fields within the chunk use size-value format (4-byte size + data, no tag).
func parseAccountChunk(data []byte, key []byte) (Entry, error) {
	fields := extractFields(data)

	entry := Entry{
		Type: "password",
	}

	// Field order within an ACCT chunk (from lastpass-cli blob.c):
	// 0: ID (plain), 1: Name (crypt), 2: Group (crypt), 3: URL (hex),
	// 4: Notes (crypt), 5: Fav (boolean), 6: ShareFromAid (skip),
	// 7: Username (crypt), 8: Password (crypt), 9: PwProtect (boolean),
	// 10: GenPw (skip), 11: SN (skip), 12: LastTouch (plain),
	// 13: AutoLogin (skip), 14: NeverAutofill (skip), 15: RealmData (skip),
	// 16: FiID (skip), 17: CustomJS (skip), 18: SubmitID (skip),
	// 19: CaptchaURL (skip), 20: UINumber (skip), 21: BasicAuth (skip),
	// 22: Method (skip), 23: Action (skip), 24: GroupID (skip),
	// 25: Deleted (skip), 26: AttachKey (plain), 27: AttachPresent (boolean),
	// 28: IndividualShare (skip), 29: NoteType (skip), 30: NoAlert (skip),
	// 31: LastModifiedGMT (plain)

	if len(fields) > 0 {
		entry.ID = string(fields[0])
	}

	if len(fields) > 1 {
		name, err := DecryptFieldRaw(fields[1], key)
		if err != nil {
			slog.Debug("failed to decrypt name field", "error", err)
		} else {
			entry.Name = sanitizeDecrypted(name)
		}
	}

	if len(fields) > 2 {
		group, err := DecryptFieldRaw(fields[2], key)
		if err != nil {
			slog.Debug("failed to decrypt group field", "error", err)
		} else {
			entry.Group = sanitizeDecrypted(group)
		}
	}

	if len(fields) > 3 {
		urlHex := string(fields[3])
		urlBytes, err := hex.DecodeString(urlHex)
		if err != nil {
			slog.Debug("failed to hex-decode URL field", "error", err)
		} else {
			entry.URL = string(urlBytes)
		}
	}

	if len(fields) > 4 {
		notes, err := DecryptFieldRaw(fields[4], key)
		if err != nil {
			slog.Debug("failed to decrypt notes field", "error", err)
		} else {
			entry.Notes = sanitizeDecrypted(notes)
		}
	}

	if len(fields) > 7 {
		username, err := DecryptFieldRaw(fields[7], key)
		if err != nil {
			slog.Debug("failed to decrypt username field", "error", err)
		} else {
			entry.Username = sanitizeDecrypted(username)
		}
	}

	if len(fields) > 8 {
		password, err := DecryptFieldRaw(fields[8], key)
		if err != nil {
			slog.Debug("failed to decrypt password field", "error", err)
		} else {
			entry.Password = sanitizeDecrypted(password)
		}
	}

	if len(fields) > 29 {
		noteType := string(fields[29])
		if noteType == "Credit Card" && entry.URL == "http://sn" {
			entry.Type = "paymentcard"
			parsePaymentCardNotes(&entry)
		}
	}

	if len(fields) > 31 {
		entry.LastModified = string(fields[31])
	}

	if len(fields) > 12 {
		entry.LastTouch = string(fields[12])
	}

	return entry, nil
}

// extractFields splits a chunk's data into sub-items using the
// size-value format (4-byte big-endian size + data). Unlike top-level
// chunks, sub-items do NOT have a 4-byte tag prefix.
func extractFields(data []byte) [][]byte {
	var fields [][]byte
	pos := 0

	for pos < len(data) {
		if pos+4 > len(data) {
			break
		}

		size := int(binary.BigEndian.Uint32(data[pos : pos+4]))
		pos += 4

		if pos+size > len(data) {
			fields = append(fields, data[pos:])
			break
		}

		fields = append(fields, data[pos:pos+size])
		pos += size
	}

	return fields
}

// parsePaymentCardNotes extracts payment card details from the Notes field.
// The notes contain key:value pairs separated by newlines.
func parsePaymentCardNotes(entry *Entry) {
	lines := strings.Split(entry.Notes, "\n")
	for _, line := range lines {
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		switch key {
		case "Name on Card":
			entry.CardholderName = value
		case "Card Type":
			entry.CardType = value
		case "Card Number":
			entry.CardNumber = value
		case "Security Code":
			entry.SecurityCode = value
		case "Start Date":
			entry.StartDate = value
		case "Expiration Date":
			entry.ExpirationDate = value
		}
	}
}
