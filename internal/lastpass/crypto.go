package lastpass

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

// DeriveKey derives a 32-byte encryption key from the user's credentials
// using PBKDF2-SHA256.
func DeriveKey(username, password string, iterations int) []byte {
	return pbkdf2.Key(
		[]byte(password),
		[]byte(username),
		iterations,
		32,
		sha256.New,
	)
}

// DeriveLoginHash computes the hex-encoded login hash used for authentication.
// It applies one additional PBKDF2-SHA256 iteration using the derived key as
// input and the password as salt.
func DeriveLoginHash(username, password string, iterations int) string {
	key := DeriveKey(username, password, iterations)
	loginHash := pbkdf2.Key(
		key,
		[]byte(password),
		1,
		32,
		sha256.New,
	)
	return hex.EncodeToString(loginHash)
}

// DecryptAES256CBC decrypts data encrypted with AES-256-CBC and removes
// PKCS7 padding from the result.
func DecryptAES256CBC(data, key, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("creating AES cipher: %w", err)
	}

	if len(data) == 0 {
		return []byte{}, nil
	}

	if len(data)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("ciphertext length %d is not a multiple of block size %d", len(data), aes.BlockSize)
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	plaintext := make([]byte, len(data))
	mode.CryptBlocks(plaintext, data)

	plaintext, err = pkcs7Unpad(plaintext, aes.BlockSize)
	if err != nil {
		return nil, fmt.Errorf("removing PKCS7 padding: %w", err)
	}

	return plaintext, nil
}

// EncryptAES256CBC encrypts data using AES-256-CBC with PKCS7 padding.
// A random 16-byte IV is generated and prepended to the ciphertext.
func EncryptAES256CBC(data, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("creating AES cipher: %w", err)
	}

	padded := pkcs7Pad(data, aes.BlockSize)

	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		return nil, fmt.Errorf("generating random IV: %w", err)
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	ciphertext := make([]byte, len(padded))
	mode.CryptBlocks(ciphertext, padded)

	result := make([]byte, 0, len(iv)+len(ciphertext))
	result = append(result, iv...)
	result = append(result, ciphertext...)

	return result, nil
}

// DecryptField decrypts a single vault field from base64-encoded format.
// CBC fields start with "!" followed by base64(IV) + "|" + base64(ciphertext).
// ECB fields are plain base64 without the "!" prefix.
// This format is used by API responses (e.g., show_website.php).
func DecryptField(field string, key []byte) (string, error) {
	if field == "" {
		return "", nil
	}

	if field[0] == '!' {
		// CBC mode: "!" + base64(IV) + "|" + base64(ciphertext)
		rest := field[1:]

		// Find the separator between IV and ciphertext
		sepIdx := -1
		for i, c := range rest {
			if c == '|' {
				sepIdx = i
				break
			}
		}
		if sepIdx == -1 {
			return "", fmt.Errorf("CBC field missing '|' separator")
		}

		ivB64 := rest[:sepIdx]
		ctB64 := rest[sepIdx+1:]

		iv, err := base64.StdEncoding.DecodeString(ivB64)
		if err != nil {
			return "", fmt.Errorf("decoding CBC IV: %w", err)
		}

		ciphertext, err := base64.StdEncoding.DecodeString(ctB64)
		if err != nil {
			return "", fmt.Errorf("decoding CBC ciphertext: %w", err)
		}

		plaintext, err := DecryptAES256CBC(ciphertext, key, iv)
		if err != nil {
			return "", fmt.Errorf("decrypting CBC field: %w", err)
		}

		return string(plaintext), nil
	}

	// ECB mode: plain base64-encoded ciphertext
	ciphertext, err := base64.StdEncoding.DecodeString(field)
	if err != nil {
		return "", fmt.Errorf("decoding ECB ciphertext: %w", err)
	}

	if len(ciphertext) == 0 {
		return "", nil
	}

	plaintext, err := decryptAES256ECB(ciphertext, key)
	if err != nil {
		return "", fmt.Errorf("decrypting ECB field: %w", err)
	}

	return string(plaintext), nil
}

// DecryptFieldRaw decrypts a vault field that may be in raw binary or base64 format.
// It tries formats in the same order as lastpass-cli's cipher_aes_decrypt:
//  1. Raw CBC: "!" (1 byte) + raw IV (16 bytes) + raw ciphertext (len >= 33, len%16 == 1)
//  2. Raw ECB: raw ciphertext (len%16 == 0)
//  3. Base64 fallback: delegates to DecryptField for base64-encoded fields
func DecryptFieldRaw(data []byte, key []byte) (string, error) {
	if len(data) == 0 {
		return "", nil
	}

	// Try raw CBC: ! + IV(16) + ciphertext, total len >= 33 and len%16 == 1
	if len(data) >= 33 && len(data)%aes.BlockSize == 1 && data[0] == '!' {
		iv := data[1:17]
		ciphertext := data[17:]

		plaintext, err := DecryptAES256CBC(ciphertext, key, iv)
		if err != nil {
			return "", fmt.Errorf("decrypting raw CBC field: %w", err)
		}

		return string(plaintext), nil
	}

	// Try raw ECB: raw ciphertext where len%16 == 0
	if len(data)%aes.BlockSize == 0 {
		plaintext, err := decryptAES256ECB(data, key)
		if err != nil {
			return "", fmt.Errorf("decrypting raw ECB field: %w", err)
		}

		return string(plaintext), nil
	}

	// Fallback: try base64-encoded format (! + base64(IV) + | + base64(ct))
	return DecryptField(string(data), key)
}

// sanitizeDecrypted removes non-printable control characters from decrypted
// text, except for common whitespace (newline, carriage return, tab).
// Some vault fields have stray padding bytes after decryption.
func sanitizeDecrypted(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if r == '\n' || r == '\r' || r == '\t' || r >= 32 {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// decryptAES256ECB decrypts data using AES-256-ECB and removes PKCS7 padding.
func decryptAES256ECB(data, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("creating AES cipher: %w", err)
	}

	if len(data)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("ciphertext length %d is not a multiple of block size %d", len(data), aes.BlockSize)
	}

	plaintext := make([]byte, len(data))
	for i := 0; i < len(data); i += aes.BlockSize {
		block.Decrypt(plaintext[i:i+aes.BlockSize], data[i:i+aes.BlockSize])
	}

	plaintext, err = pkcs7Unpad(plaintext, aes.BlockSize)
	if err != nil {
		return nil, fmt.Errorf("removing PKCS7 padding: %w", err)
	}

	return plaintext, nil
}

// pkcs7Pad adds PKCS7 padding to data to make it a multiple of blockSize.
func pkcs7Pad(data []byte, blockSize int) []byte {
	padding := blockSize - (len(data) % blockSize)
	padded := make([]byte, len(data)+padding)
	copy(padded, data)
	for i := len(data); i < len(padded); i++ {
		padded[i] = byte(padding)
	}
	return padded
}

// pkcs7Unpad removes PKCS7 padding from the decrypted data.
func pkcs7Unpad(data []byte, blockSize int) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("data is empty")
	}

	padding := int(data[len(data)-1])
	if padding == 0 || padding > blockSize {
		return nil, fmt.Errorf("invalid padding value: %d", padding)
	}

	if padding > len(data) {
		return nil, fmt.Errorf("padding %d exceeds data length %d", padding, len(data))
	}

	for i := len(data) - padding; i < len(data); i++ {
		if data[i] != byte(padding) {
			return nil, fmt.Errorf("invalid PKCS7 padding")
		}
	}

	return data[:len(data)-padding], nil
}
