// debug-vault downloads the vault blob, decrypts all entries, and updates
// the GCS persisted state with correctly decrypted entries.
package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"cloud.google.com/go/storage"
	"lastpass-mcp/internal/lastpass"
)

type persistedState struct {
	Tokens  map[string]persistedToken  `json:"tokens"`
	Clients map[string]persistedClient `json:"clients"`
	SavedAt time.Time                  `json:"saved_at"`
}

type persistedToken struct {
	BearerToken string           `json:"bearer_token"`
	Session     persistedSession `json:"session"`
	ClientID    string           `json:"client_id"`
	CreatedAt   time.Time        `json:"created_at"`
}

type persistedSession struct {
	Email         string           `json:"email"`
	DecryptionKey []byte           `json:"decryption_key"`
	SessionID     string           `json:"session_id"`
	CSRFToken     string           `json:"csrf_token"`
	Entries       []lastpass.Entry `json:"entries"`
	CreatedAt     time.Time        `json:"created_at"`
}

type persistedClient struct {
	ClientID     string   `json:"client_id"`
	ClientSecret string   `json:"client_secret"`
	RedirectURIs []string `json:"redirect_uris"`
}

func main() {
	ctx := context.Background()
	bucket := "scmlastpass-state-prd"

	client, err := storage.NewClient(ctx)
	if err != nil {
		log.Fatal("storage client:", err)
	}
	defer client.Close()

	// Read current state
	obj := client.Bucket(bucket).Object("oauth2-state.json")
	reader, err := obj.NewReader(ctx)
	if err != nil {
		log.Fatal("read GCS:", err)
	}
	data, err := io.ReadAll(reader)
	if err != nil {
		log.Fatal("read state data:", err)
	}
	reader.Close()

	var state persistedState
	if err := json.Unmarshal(data, &state); err != nil {
		log.Fatal("parse state JSON:", err)
	}

	fmt.Printf("Loaded %d tokens, %d clients\n", len(state.Tokens), len(state.Clients))

	// Get session info from first token
	var sessionID string
	var key []byte
	for _, t := range state.Tokens {
		sessionID = t.Session.SessionID
		key = t.Session.DecryptionKey
		fmt.Printf("Email: %s, key length: %d\n", t.Session.Email, len(key))
		break
	}

	if len(key) == 0 {
		log.Fatal("no decryption key found")
	}

	// Download vault
	reqURL := "https://lastpass.com/getaccts.php?mobile=1&b64=1&hash=0.0&hasplugin=3.0.23&requestsrc=cli"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		log.Fatal("create vault request:", err)
	}
	req.AddCookie(&http.Cookie{Name: "PHPSESSID", Value: sessionID})
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Fatal("vault request:", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatal("read vault response:", err)
	}

	if resp.StatusCode != 200 {
		fmt.Printf("Error: status %d, body: %s\n", resp.StatusCode, string(body)[:min(200, len(body))])
		os.Exit(1)
	}

	blob, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(body)))
	if err != nil {
		log.Fatal("base64 decode vault:", err)
	}
	fmt.Printf("Vault blob: %d bytes\n", len(blob))

	// Parse vault
	entries, err := lastpass.ParseVaultBlob(blob, key)
	if err != nil {
		log.Fatal("parse vault:", err)
	}

	named := 0
	withUser := 0
	for _, e := range entries {
		if e.Name != "" {
			named++
		}
		if e.Username != "" {
			withUser++
		}
	}
	fmt.Printf("Parsed: %d entries, %d with name, %d with username\n", len(entries), named, withUser)

	if os.Getenv("DRY_RUN") == "1" {
		fmt.Println("DRY_RUN=1, not updating GCS")
		return
	}

	// Update all tokens with the new entries
	for k, t := range state.Tokens {
		t.Session.Entries = entries
		state.Tokens[k] = t
	}
	state.SavedAt = time.Now()

	// Write back to GCS
	newData, err := json.Marshal(state)
	if err != nil {
		log.Fatal("marshal state:", err)
	}
	writer := client.Bucket(bucket).Object("oauth2-state.json").NewWriter(ctx)
	writer.ContentType = "application/json"
	if _, err := writer.Write(newData); err != nil {
		log.Fatal("write GCS:", err)
	}
	if err := writer.Close(); err != nil {
		log.Fatal("close writer:", err)
	}

	fmt.Printf("Updated GCS state with %d correctly decrypted entries\n", len(entries))
}
