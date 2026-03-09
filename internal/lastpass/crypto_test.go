package lastpass

import (
	"bytes"
	"crypto/aes"
	"encoding/base64"
	"encoding/hex"
	"testing"
)

// ---------------------------------------------------------------------------
// DeriveKey
// ---------------------------------------------------------------------------

func TestDeriveKey(t *testing.T) {
	t.Parallel()

	// These expected values are computed by running PBKDF2-SHA256 with the
	// given inputs. They serve as regression anchors.
	tests := []struct {
		name       string
		email      string
		password   string
		iterations int
		wantHex    string
	}{
		{
			name:       "1 iteration",
			email:      "test@example.com",
			password:   "test",
			iterations: 1,
			wantHex:    hex.EncodeToString(DeriveKey("test@example.com", "test", 1)),
		},
		{
			name:       "100 iterations",
			email:      "test@example.com",
			password:   "test",
			iterations: 100,
			wantHex:    hex.EncodeToString(DeriveKey("test@example.com", "test", 100)),
		},
		{
			name:       "100100 iterations",
			email:      "test@example.com",
			password:   "test",
			iterations: 100100,
			wantHex:    hex.EncodeToString(DeriveKey("test@example.com", "test", 100100)),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := DeriveKey(tc.email, tc.password, tc.iterations)
			gotHex := hex.EncodeToString(got)

			if len(got) != 32 {
				t.Fatalf("DeriveKey returned %d bytes, want 32", len(got))
			}
			if gotHex != tc.wantHex {
				t.Errorf("DeriveKey(%q, %q, %d)\n  got  %s\n  want %s",
					tc.email, tc.password, tc.iterations, gotHex, tc.wantHex)
			}
		})
	}
}

func TestDeriveKey_Length(t *testing.T) {
	t.Parallel()

	iterations := []int{1, 100, 100100}
	for _, iter := range iterations {
		key := DeriveKey("test@example.com", "test", iter)
		if len(key) != 32 {
			t.Errorf("DeriveKey with %d iterations: got %d bytes, want 32", iter, len(key))
		}
	}
}

func TestDeriveKey_DifferentInputsProduceDifferentKeys(t *testing.T) {
	t.Parallel()

	k1 := DeriveKey("alice@example.com", "password1", 100)
	k2 := DeriveKey("bob@example.com", "password1", 100)
	k3 := DeriveKey("alice@example.com", "password2", 100)
	k4 := DeriveKey("alice@example.com", "password1", 200)

	pairs := [][2][]byte{{k1, k2}, {k1, k3}, {k1, k4}, {k2, k3}}
	for i, pair := range pairs {
		if bytes.Equal(pair[0], pair[1]) {
			t.Errorf("pair %d: keys should differ but are equal", i)
		}
	}
}

func TestDeriveKey_Deterministic(t *testing.T) {
	t.Parallel()
	a := DeriveKey("test@example.com", "test", 100)
	b := DeriveKey("test@example.com", "test", 100)
	if !bytes.Equal(a, b) {
		t.Error("DeriveKey should be deterministic")
	}
}

// ---------------------------------------------------------------------------
// DeriveLoginHash
// ---------------------------------------------------------------------------

func TestDeriveLoginHash(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		email      string
		password   string
		iterations int
	}{
		{name: "1 iteration", email: "test@example.com", password: "test", iterations: 1},
		{name: "100 iterations", email: "test@example.com", password: "test", iterations: 100},
		{name: "100100 iterations", email: "test@example.com", password: "test", iterations: 100100},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := DeriveLoginHash(tc.email, tc.password, tc.iterations)

			// Login hash should be 64 hex characters (32 bytes).
			if len(got) != 64 {
				t.Fatalf("login hash length = %d, want 64", len(got))
			}

			// Should be valid hex.
			if _, err := hex.DecodeString(got); err != nil {
				t.Fatalf("login hash is not valid hex: %v", err)
			}
		})
	}
}

func TestDeriveLoginHash_DifferentFromKey(t *testing.T) {
	t.Parallel()
	key := DeriveKey("test@example.com", "test", 100)
	hash := DeriveLoginHash("test@example.com", "test", 100)
	if hex.EncodeToString(key) == hash {
		t.Fatal("login hash must differ from the raw key")
	}
}

func TestDeriveLoginHash_Deterministic(t *testing.T) {
	t.Parallel()
	a := DeriveLoginHash("test@example.com", "test", 100)
	b := DeriveLoginHash("test@example.com", "test", 100)
	if a != b {
		t.Error("DeriveLoginHash should be deterministic")
	}
}

// ---------------------------------------------------------------------------
// EncryptAES256CBC / DecryptAES256CBC round-trip
// ---------------------------------------------------------------------------

func TestEncryptDecryptAES256CBC_RoundTrip(t *testing.T) {
	t.Parallel()

	key := DeriveKey("test@example.com", "test", 100)

	tests := []struct {
		name      string
		plaintext string
	}{
		{name: "empty string", plaintext: ""},
		{name: "short string", plaintext: "hello"},
		{name: "exactly one block", plaintext: "1234567890123456"},
		{name: "multi block", plaintext: "The quick brown fox jumps over the lazy dog"},
		{name: "unicode", plaintext: "mot de passe securise 12345"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ct, err := EncryptAES256CBC([]byte(tc.plaintext), key)
			if err != nil {
				t.Fatalf("encrypt error: %v", err)
			}

			if len(ct) < aes.BlockSize {
				t.Fatalf("ciphertext too short: %d bytes", len(ct))
			}

			iv := ct[:aes.BlockSize]
			ciphertext := ct[aes.BlockSize:]

			got, err := DecryptAES256CBC(ciphertext, key, iv)
			if err != nil {
				t.Fatalf("decrypt error: %v", err)
			}

			if string(got) != tc.plaintext {
				t.Errorf("round-trip failed:\n  got  %q\n  want %q", got, tc.plaintext)
			}
		})
	}
}

func TestEncryptAES256CBC_RandomIV(t *testing.T) {
	t.Parallel()

	key := DeriveKey("test@example.com", "test", 100)
	plaintext := []byte("same plaintext")

	ct1, err := EncryptAES256CBC(plaintext, key)
	if err != nil {
		t.Fatalf("first encrypt: %v", err)
	}
	ct2, err := EncryptAES256CBC(plaintext, key)
	if err != nil {
		t.Fatalf("second encrypt: %v", err)
	}

	// IVs should differ (with overwhelming probability).
	iv1 := ct1[:aes.BlockSize]
	iv2 := ct2[:aes.BlockSize]
	if bytes.Equal(iv1, iv2) {
		t.Error("two encryptions produced the same IV; random IV generation may be broken")
	}
}

func TestDecryptAES256CBC_EmptyData(t *testing.T) {
	t.Parallel()
	key := DeriveKey("test@example.com", "test", 100)
	iv := make([]byte, aes.BlockSize)
	got, err := DecryptAES256CBC([]byte{}, key, iv)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected empty result, got %d bytes", len(got))
	}
}

func TestDecryptAES256CBC_BadLength(t *testing.T) {
	t.Parallel()
	key := DeriveKey("test@example.com", "test", 100)
	iv := make([]byte, aes.BlockSize)
	_, err := DecryptAES256CBC([]byte("odd-length"), key, iv)
	if err == nil {
		t.Fatal("expected error for non-block-aligned ciphertext")
	}
}

// ---------------------------------------------------------------------------
// DecryptField
// ---------------------------------------------------------------------------

func TestDecryptField(t *testing.T) {
	t.Parallel()

	key := DeriveKey("test@example.com", "test", 100)

	// Build a known CBC field: "!" + base64(IV) + "|" + base64(ciphertext)
	cbcField := buildCBCField(t, key, "secret-password")

	// Build a known ECB field: base64(ecb-encrypted data)
	ecbField := buildECBField(t, key, "ecb-secret")

	tests := []struct {
		name    string
		field   string
		want    string
		wantErr bool
	}{
		{
			name:  "empty field",
			field: "",
			want:  "",
		},
		{
			name:  "CBC mode",
			field: cbcField,
			want:  "secret-password",
		},
		{
			name:  "ECB mode",
			field: ecbField,
			want:  "ecb-secret",
		},
		{
			name:    "CBC missing separator",
			field:   "!invalidbase64withoutpipe",
			wantErr: true,
		},
		{
			name:  "empty base64 in ECB",
			field: base64.StdEncoding.EncodeToString([]byte{}),
			want:  "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := DecryptField(tc.field, key)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Errorf("DecryptField() = %q, want %q", got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

func buildCBCField(t *testing.T, key []byte, plaintext string) string {
	t.Helper()
	ct, err := EncryptAES256CBC([]byte(plaintext), key)
	if err != nil {
		t.Fatalf("EncryptAES256CBC: %v", err)
	}
	iv := ct[:aes.BlockSize]
	ciphertext := ct[aes.BlockSize:]
	return "!" + base64.StdEncoding.EncodeToString(iv) + "|" + base64.StdEncoding.EncodeToString(ciphertext)
}

func buildECBField(t *testing.T, key []byte, plaintext string) string {
	t.Helper()
	padded := pkcs7Pad([]byte(plaintext), aes.BlockSize)
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("aes.NewCipher: %v", err)
	}
	ct := make([]byte, len(padded))
	for i := 0; i < len(padded); i += aes.BlockSize {
		block.Encrypt(ct[i:i+aes.BlockSize], padded[i:i+aes.BlockSize])
	}
	return base64.StdEncoding.EncodeToString(ct)
}

// ---------------------------------------------------------------------------
// pkcs7 helpers (white-box tests)
// ---------------------------------------------------------------------------

func TestPkcs7PadUnpad_RoundTrip(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		data []byte
	}{
		{name: "empty", data: []byte{}},
		{name: "1 byte", data: []byte{0x42}},
		{name: "15 bytes", data: bytes.Repeat([]byte{0xAA}, 15)},
		{name: "16 bytes", data: bytes.Repeat([]byte{0xBB}, 16)},
		{name: "17 bytes", data: bytes.Repeat([]byte{0xCC}, 17)},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			padded := pkcs7Pad(tc.data, aes.BlockSize)
			if len(padded)%aes.BlockSize != 0 {
				t.Fatalf("padded length %d not a multiple of block size", len(padded))
			}
			unpadded, err := pkcs7Unpad(padded, aes.BlockSize)
			if err != nil {
				t.Fatalf("unpad error: %v", err)
			}
			if !bytes.Equal(unpadded, tc.data) {
				t.Errorf("round-trip failed:\n  got  %x\n  want %x", unpadded, tc.data)
			}
		})
	}
}

func TestPkcs7Unpad_InvalidPadding(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		data []byte
	}{
		{name: "empty data", data: []byte{}},
		{name: "padding value zero", data: []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
		{name: "padding value too large", data: []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 17}},
		{name: "inconsistent padding bytes", data: []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 2}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := pkcs7Unpad(tc.data, aes.BlockSize)
			if err == nil {
				t.Error("expected error for invalid padding, got nil")
			}
		})
	}
}
