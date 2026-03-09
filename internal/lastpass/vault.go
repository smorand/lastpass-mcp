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
	ID           string
	Name         string
	URL          string
	Username     string
	Password     string
	Notes        string
	Type         string // "password" or "paymentcard"
	Group        string
	LastModified string
	LastTouch    string

	// Payment card specific fields (populated when Type is "paymentcard")
	CardholderName string
	CardType       string
	CardNumber     string
	SecurityCode   string
	StartDate      string
	ExpirationDate string
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
// Fields within the chunk use the same tag-length-value format as top-level chunks.
func parseAccountChunk(data []byte, key []byte) (Entry, error) {
	fields := extractFields(data)

	entry := Entry{
		Type: "password",
	}

	// Field indices within an ACCT chunk (0-based):
	// 0: ID, 1: Name, 2: Group, 3: URL, 4: Notes
	// 9: Username, 10: Password
	// 24: NoteType
	// 33: LastModified
	// 40: LastTouch

	if len(fields) > 0 {
		entry.ID = string(fields[0])
	}

	if len(fields) > 1 {
		name, err := DecryptField(string(fields[1]), key)
		if err != nil {
			slog.Debug("failed to decrypt name field", "error", err)
		} else {
			entry.Name = name
		}
	}

	if len(fields) > 2 {
		group, err := DecryptField(string(fields[2]), key)
		if err != nil {
			slog.Debug("failed to decrypt group field", "error", err)
		} else {
			entry.Group = group
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
		notes, err := DecryptField(string(fields[4]), key)
		if err != nil {
			slog.Debug("failed to decrypt notes field", "error", err)
		} else {
			entry.Notes = notes
		}
	}

	if len(fields) > 9 {
		username, err := DecryptField(string(fields[9]), key)
		if err != nil {
			slog.Debug("failed to decrypt username field", "error", err)
		} else {
			entry.Username = username
		}
	}

	if len(fields) > 10 {
		password, err := DecryptField(string(fields[10]), key)
		if err != nil {
			slog.Debug("failed to decrypt password field", "error", err)
		} else {
			entry.Password = password
		}
	}

	if len(fields) > 24 {
		noteType := string(fields[24])
		if noteType == "Credit Card" && entry.URL == "http://sn" {
			entry.Type = "paymentcard"
			parsePaymentCardNotes(&entry)
		}
	}

	if len(fields) > 33 {
		entry.LastModified = string(fields[33])
	}

	if len(fields) > 40 {
		entry.LastTouch = string(fields[40])
	}

	return entry, nil
}

// extractFields splits a chunk's data into sub-items using the same
// tag-length-value format (4-byte tag + 4-byte big-endian size + data).
// Only the data portion of each sub-item is returned.
func extractFields(data []byte) [][]byte {
	var fields [][]byte
	pos := 0

	for pos < len(data) {
		if pos+8 > len(data) {
			break
		}

		// Skip the 4-byte sub-item tag
		size := int(binary.BigEndian.Uint32(data[pos+4 : pos+8]))
		pos += 8

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
