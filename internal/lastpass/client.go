package lastpass

import (
	"context"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	baseURL          = "https://lastpass.com"
	maxRetryDuration = 1 * time.Minute
)

// Client is the LastPass API client that handles authentication,
// vault operations, and entry management.
type Client struct {
	httpClient *http.Client
}

// Session holds the authenticated session state. The DecryptionKey field
// is intentionally left without JSON tags to prevent accidental serialization.
type Session struct {
	Email         string    `json:"email"`
	DecryptionKey []byte    // no JSON tag: must never be serialized
	SessionID     string    `json:"session_id"`
	CSRFToken     string    `json:"csrf_token"`
	Entries       []Entry   `json:"entries"`
	CreatedAt     time.Time `json:"created_at"`
}

// loginResponse represents the XML response from the LastPass login endpoint.
type loginResponse struct {
	XMLName xml.Name   `xml:"response"`
	OK      loginOK    `xml:"ok"`
	Error   loginError `xml:"error"`
}

type loginOK struct {
	SessionID string `xml:"sessionid,attr"`
	Token     string `xml:"token,attr"`
}

type loginError struct {
	Message string `xml:"message,attr"`
	Cause   string `xml:"cause,attr"`
}

// NewClient creates a new LastPass API client with a default HTTP client.
func NewClient() *Client {
	return &Client{
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// Login authenticates with LastPass and downloads/decrypts the vault.
// It performs the full login flow: iteration lookup, key derivation,
// authentication, vault download, and decryption.
func (c *Client) Login(ctx context.Context, email, password string) (*Session, error) {
	slog.Info("starting LastPass login", "email", email)

	// Step 1: Get iteration count
	iterations, err := c.getIterations(ctx, email)
	if err != nil {
		return nil, fmt.Errorf("getting iterations: %w", err)
	}
	slog.Debug("retrieved iteration count", "iterations", iterations)

	// Step 2: Derive key and login hash
	key := DeriveKey(email, password, iterations)
	loginHash := DeriveLoginHash(email, password, iterations)

	// Step 3: Authenticate
	sessionID, csrfToken, err := c.authenticate(ctx, email, loginHash, iterations)
	if err != nil {
		return nil, fmt.Errorf("authenticating: %w", err)
	}
	slog.Info("authentication successful")

	session := &Session{
		Email:         email,
		DecryptionKey: key,
		SessionID:     sessionID,
		CSRFToken:     csrfToken,
		CreatedAt:     time.Now(),
	}

	// Step 4: Download and parse vault
	if err := c.downloadAndParseVault(ctx, session); err != nil {
		return nil, fmt.Errorf("downloading vault: %w", err)
	}

	slog.Info("login complete", "entry_count", len(session.Entries))
	return session, nil
}

// Logout terminates the authenticated session with LastPass.
func (c *Client) Logout(ctx context.Context, session *Session) error {
	slog.Info("logging out of LastPass")

	form := url.Values{
		"method":     {"cli"},
		"noredirect": {"1"},
		"token":      {session.CSRFToken},
	}

	var logoutErr error
	err := RetryWithBackoff(ctx, maxRetryDuration, func() error {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+"/logout.php", strings.NewReader(form.Encode()))
		if err != nil {
			logoutErr = fmt.Errorf("creating logout request: %w", err)
			return nil // do not retry request creation errors
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.AddCookie(&http.Cookie{Name: "PHPSESSID", Value: session.SessionID})

		resp, err := c.httpClient.Do(req)
		if err != nil {
			return fmt.Errorf("sending logout request: %w", err)
		}
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("logout returned status %d", resp.StatusCode)
		}
		return nil
	})
	if logoutErr != nil {
		return logoutErr
	}
	if err != nil {
		return fmt.Errorf("logout failed: %w", err)
	}

	slog.Info("logout successful")
	return nil
}

// CreateEntry creates a new entry in the LastPass vault via the API.
func (c *Client) CreateEntry(ctx context.Context, session *Session, entry Entry) (*Entry, error) {
	slog.Info("creating new vault entry", "name", entry.Name)
	return c.upsertEntry(ctx, session, entry, "0")
}

// UpdateEntry updates an existing entry in the LastPass vault via the API.
func (c *Client) UpdateEntry(ctx context.Context, session *Session, entry Entry) (*Entry, error) {
	slog.Info("updating vault entry", "id", entry.ID, "name", entry.Name)
	return c.upsertEntry(ctx, session, entry, entry.ID)
}

// RefreshVault re-downloads and parses the vault, updating the session entries.
func (c *Client) RefreshVault(ctx context.Context, session *Session) error {
	slog.Info("refreshing vault")
	if err := c.downloadAndParseVault(ctx, session); err != nil {
		return fmt.Errorf("refreshing vault: %w", err)
	}
	slog.Info("vault refreshed", "entry_count", len(session.Entries))
	return nil
}

// getIterations fetches the PBKDF2 iteration count for the given email.
func (c *Client) getIterations(ctx context.Context, email string) (int, error) {
	var iterations int

	err := RetryWithBackoff(ctx, maxRetryDuration, func() error {
		reqURL := fmt.Sprintf("%s/iterations.php?email=%s", baseURL, url.QueryEscape(email))
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
		if err != nil {
			return fmt.Errorf("creating iterations request: %w", err)
		}

		resp, err := c.httpClient.Do(req)
		if err != nil {
			return fmt.Errorf("sending iterations request: %w", err)
		}
		defer func() { _ = resp.Body.Close() }()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("reading iterations response: %w", err)
		}

		iterations, err = strconv.Atoi(strings.TrimSpace(string(body)))
		if err != nil {
			return fmt.Errorf("parsing iteration count %q: %w", string(body), err)
		}

		return nil
	})
	if err != nil {
		return 0, err
	}

	return iterations, nil
}

// authenticate performs the login POST and returns the session ID and CSRF token.
func (c *Client) authenticate(ctx context.Context, email, loginHash string, iterations int) (string, string, error) {
	form := url.Values{
		"method":               {"cli"},
		"xml":                  {"1"},
		"username":             {email},
		"hash":                 {loginHash},
		"iterations":           {strconv.Itoa(iterations)},
		"includeprivatekeyenc": {"1"},
		"outofbandsupported":   {"0"},
	}

	var sessionID, csrfToken string

	err := RetryWithBackoff(ctx, maxRetryDuration, func() error {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+"/login.php", strings.NewReader(form.Encode()))
		if err != nil {
			return fmt.Errorf("creating login request: %w", err)
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		resp, err := c.httpClient.Do(req)
		if err != nil {
			return fmt.Errorf("sending login request: %w", err)
		}
		defer func() { _ = resp.Body.Close() }()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("reading login response: %w", err)
		}

		var loginResp loginResponse
		if err := xml.Unmarshal(body, &loginResp); err != nil {
			return fmt.Errorf("parsing login response XML: %w", err)
		}

		if loginResp.Error.Cause != "" || loginResp.Error.Message != "" {
			return fmt.Errorf("login error: %s (cause: %s)", loginResp.Error.Message, loginResp.Error.Cause)
		}

		if loginResp.OK.SessionID == "" {
			return fmt.Errorf("login response missing session ID")
		}

		sessionID = loginResp.OK.SessionID
		csrfToken = loginResp.OK.Token

		return nil
	})
	if err != nil {
		return "", "", err
	}

	return sessionID, csrfToken, nil
}

// downloadAndParseVault downloads the vault blob and decrypts all entries.
func (c *Client) downloadAndParseVault(ctx context.Context, session *Session) error {
	var blob []byte

	err := RetryWithBackoff(ctx, maxRetryDuration, func() error {
		reqURL := baseURL + "/getaccts.php?mobile=1&b64=1&hash=0.0&hasplugin=3.0.23&requestsrc=cli"
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
		if err != nil {
			return fmt.Errorf("creating vault request: %w", err)
		}
		req.AddCookie(&http.Cookie{Name: "PHPSESSID", Value: session.SessionID})

		resp, err := c.httpClient.Do(req)
		if err != nil {
			return fmt.Errorf("sending vault request: %w", err)
		}
		defer func() { _ = resp.Body.Close() }()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("reading vault response: %w", err)
		}

		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("vault download returned status %d", resp.StatusCode)
		}

		blob, err = base64.StdEncoding.DecodeString(strings.TrimSpace(string(body)))
		if err != nil {
			return fmt.Errorf("base64-decoding vault blob: %w", err)
		}

		return nil
	})
	if err != nil {
		return err
	}

	entries, err := ParseVaultBlob(blob, session.DecryptionKey)
	if err != nil {
		return fmt.Errorf("parsing vault blob: %w", err)
	}

	session.Entries = entries
	return nil
}

// upsertEntry creates or updates a vault entry via the show_website.php endpoint.
// When aid is "0", a new entry is created; otherwise the existing entry is updated.
func (c *Client) upsertEntry(ctx context.Context, session *Session, entry Entry, aid string) (*Entry, error) {
	encryptedName, err := EncryptAES256CBC([]byte(entry.Name), session.DecryptionKey)
	if err != nil {
		return nil, fmt.Errorf("encrypting name: %w", err)
	}

	encryptedUsername, err := EncryptAES256CBC([]byte(entry.Username), session.DecryptionKey)
	if err != nil {
		return nil, fmt.Errorf("encrypting username: %w", err)
	}

	encryptedPassword, err := EncryptAES256CBC([]byte(entry.Password), session.DecryptionKey)
	if err != nil {
		return nil, fmt.Errorf("encrypting password: %w", err)
	}

	encryptedNotes, err := EncryptAES256CBC([]byte(entry.Notes), session.DecryptionKey)
	if err != nil {
		return nil, fmt.Errorf("encrypting notes: %w", err)
	}

	encryptedGroup, err := EncryptAES256CBC([]byte(entry.Group), session.DecryptionKey)
	if err != nil {
		return nil, fmt.Errorf("encrypting group: %w", err)
	}

	form := url.Values{
		"method":   {"cli"},
		"token":    {session.CSRFToken},
		"aid":      {aid},
		"url":      {entry.URL},
		"name":     {base64.StdEncoding.EncodeToString(encryptedName)},
		"username": {base64.StdEncoding.EncodeToString(encryptedUsername)},
		"password": {base64.StdEncoding.EncodeToString(encryptedPassword)},
		"extra":    {base64.StdEncoding.EncodeToString(encryptedNotes)},
		"grouping": {base64.StdEncoding.EncodeToString(encryptedGroup)},
	}

	var resultEntry *Entry

	err = RetryWithBackoff(ctx, maxRetryDuration, func() error {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+"/show_website.php", strings.NewReader(form.Encode()))
		if err != nil {
			return fmt.Errorf("creating upsert request: %w", err)
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.AddCookie(&http.Cookie{Name: "PHPSESSID", Value: session.SessionID})

		resp, err := c.httpClient.Do(req)
		if err != nil {
			return fmt.Errorf("sending upsert request: %w", err)
		}
		defer func() { _ = resp.Body.Close() }()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("reading upsert response: %w", err)
		}

		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("upsert returned status %d: %s", resp.StatusCode, string(body))
		}

		resultEntry = &Entry{
			ID:       aid,
			Name:     entry.Name,
			URL:      entry.URL,
			Username: entry.Username,
			Password: entry.Password,
			Notes:    entry.Notes,
			Group:    entry.Group,
			Type:     entry.Type,
		}

		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("upserting entry: %w", err)
	}

	return resultEntry, nil
}
