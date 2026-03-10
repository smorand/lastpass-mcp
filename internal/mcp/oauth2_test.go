package mcp

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"lastpass-mcp/internal/lastpass"
)

// ---------------------------------------------------------------------------
// isRedirectURIAllowed
// ---------------------------------------------------------------------------

func TestIsRedirectURIAllowed(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		uri  string
		want bool
	}{
		{"localhost:8000 http", "http://localhost:8000/callback", true},
		{"localhost:3000 http", "http://localhost:3000/callback", true},
		{"127.0.0.1:8000 http", "http://127.0.0.1:8000/callback", true},
		{"127.0.0.1:3000 http", "http://127.0.0.1:3000/callback", true},
		{"localhost:8000 root path", "http://localhost:8000/", true},
		{"production callback exact", "https://lastpass.mcp.scm-platform.org/oauth/callback", true},
		{"localhost wrong port", "http://localhost:9999/callback", false},
		{"external domain http", "http://evil.example.com/callback", false},
		{"external domain https", "https://evil.example.com/callback", false},
		{"fragment present", "http://localhost:8000/callback#frag", false},
		{"empty string", "", false},
		{"malformed URI", "://not-a-uri", false},
		{"production with extra path", "https://lastpass.mcp.scm-platform.org/oauth/callback/extra", false},
		{"localhost https wrong scheme", "https://localhost:8000/callback", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := isRedirectURIAllowed(tc.uri)
			if got != tc.want {
				t.Errorf("isRedirectURIAllowed(%q) = %v, want %v", tc.uri, got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// HandleClientRegistration
// ---------------------------------------------------------------------------

func TestHandleClientRegistration(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		body       string
		wantStatus int
		wantError  string
	}{
		{
			name:       "valid localhost redirect",
			body:       `{"redirect_uris":["http://localhost:8000/callback"],"client_name":"test"}`,
			wantStatus: http.StatusCreated,
		},
		{
			name:       "valid 127.0.0.1 redirect",
			body:       `{"redirect_uris":["http://127.0.0.1:3000/cb"],"client_name":"test"}`,
			wantStatus: http.StatusCreated,
		},
		{
			name:       "reject external HTTP",
			body:       `{"redirect_uris":["http://evil.com/callback"],"client_name":"test"}`,
			wantStatus: http.StatusBadRequest,
			wantError:  "invalid_request",
		},
		{
			name:       "reject empty redirect_uris",
			body:       `{"redirect_uris":[],"client_name":"test"}`,
			wantStatus: http.StatusBadRequest,
			wantError:  "invalid_request",
		},
		{
			name:       "reject malformed URI",
			body:       `{"redirect_uris":["://bad"],"client_name":"test"}`,
			wantStatus: http.StatusBadRequest,
			wantError:  "invalid_request",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			s := newTestOAuth2Server()

			req := httptest.NewRequest(http.MethodPost, "/oauth/register", strings.NewReader(tc.body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			s.HandleClientRegistration(w, req)

			if w.Code != tc.wantStatus {
				t.Errorf("status = %d, want %d; body = %s", w.Code, tc.wantStatus, w.Body.String())
			}
			if tc.wantError != "" {
				var errResp TokenErrorResponse
				_ = json.Unmarshal(w.Body.Bytes(), &errResp)
				if errResp.Error != tc.wantError {
					t.Errorf("error = %q, want %q", errResp.Error, tc.wantError)
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// handleAuthorizeGet: unregistered client
// ---------------------------------------------------------------------------

func TestHandleAuthorizeGet_UnregisteredClient(t *testing.T) {
	t.Parallel()
	s := newTestOAuth2Server()

	q := url.Values{
		"client_id":             {"unknown-client"},
		"redirect_uri":          {"http://localhost:8000/callback"},
		"response_type":         {"code"},
		"code_challenge":        {"challenge123"},
		"code_challenge_method": {"S256"},
	}
	req := httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+q.Encode(), nil)
	w := httptest.NewRecorder()

	s.HandleAuthorize(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", w.Code, http.StatusUnauthorized)
	}

	var errResp TokenErrorResponse
	_ = json.Unmarshal(w.Body.Bytes(), &errResp)
	if errResp.Error != "invalid_client" {
		t.Errorf("error = %q, want %q", errResp.Error, "invalid_client")
	}
}

// ---------------------------------------------------------------------------
// handleAuthorizeGet: invalid redirect_uri
// ---------------------------------------------------------------------------

func TestHandleAuthorizeGet_InvalidRedirectURI(t *testing.T) {
	t.Parallel()
	s := newTestOAuth2Server()
	registerTestClient(s, "test-client", "http://localhost:8000/callback")

	q := url.Values{
		"client_id":             {"test-client"},
		"redirect_uri":          {"http://evil.com/steal"},
		"response_type":         {"code"},
		"code_challenge":        {"challenge123"},
		"code_challenge_method": {"S256"},
	}
	req := httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+q.Encode(), nil)
	w := httptest.NewRecorder()

	s.HandleAuthorize(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}

	var errResp TokenErrorResponse
	_ = json.Unmarshal(w.Body.Bytes(), &errResp)
	if errResp.Error != "invalid_request" {
		t.Errorf("error = %q, want %q", errResp.Error, "invalid_request")
	}
}

// ---------------------------------------------------------------------------
// handleAuthorizeGet: missing PKCE
// ---------------------------------------------------------------------------

func TestHandleAuthorizeGet_MissingPKCE(t *testing.T) {
	t.Parallel()
	s := newTestOAuth2Server()
	registerTestClient(s, "test-client", "http://localhost:8000/callback")

	q := url.Values{
		"client_id":     {"test-client"},
		"redirect_uri":  {"http://localhost:8000/callback"},
		"response_type": {"code"},
	}
	req := httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+q.Encode(), nil)
	w := httptest.NewRecorder()

	s.HandleAuthorize(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}

	var errResp TokenErrorResponse
	_ = json.Unmarshal(w.Body.Bytes(), &errResp)
	if errResp.Error != "invalid_request" {
		t.Errorf("error = %q, want %q", errResp.Error, "invalid_request")
	}
}

// ---------------------------------------------------------------------------
// handleAuthorizeGet: success (renders login page)
// ---------------------------------------------------------------------------

func TestHandleAuthorizeGet_Success(t *testing.T) {
	t.Parallel()
	s := newTestOAuth2Server()
	registerTestClient(s, "test-client", "http://localhost:8000/callback")

	verifier := "test-verifier-string-that-is-long-enough"
	challenge := computeS256Challenge(verifier)

	q := url.Values{
		"client_id":             {"test-client"},
		"redirect_uri":          {"http://localhost:8000/callback"},
		"response_type":         {"code"},
		"state":                 {"client-state"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
	req := httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+q.Encode(), nil)
	w := httptest.NewRecorder()

	s.HandleAuthorize(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d; body = %s", w.Code, http.StatusOK, w.Body.String())
	}
	ct := w.Header().Get("Content-Type")
	if !strings.Contains(ct, "text/html") {
		t.Errorf("Content-Type = %q, want text/html", ct)
	}
}

// ---------------------------------------------------------------------------
// HandleToken: PKCE required (missing code_verifier)
// ---------------------------------------------------------------------------

func TestHandleToken_PKCERequired(t *testing.T) {
	t.Parallel()
	s := newTestOAuth2Server()

	// Manually plant an auth code with a challenge
	verifier := "my-test-verifier-long-enough"
	challenge := computeS256Challenge(verifier)

	s.mu.Lock()
	s.codes["test-code"] = &AuthCode{
		Code:          "test-code",
		ClientID:      "test-client",
		RedirectURI:   "http://localhost:8000/callback",
		CodeChallenge: challenge,
		CodeMethod:    "S256",
	}
	s.mu.Unlock()

	form := url.Values{
		"grant_type": {"authorization_code"},
		"code":       {"test-code"},
		"client_id":  {"test-client"},
	}
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	s.HandleToken(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}

	var errResp TokenErrorResponse
	_ = json.Unmarshal(w.Body.Bytes(), &errResp)
	if errResp.Error != "invalid_request" {
		t.Errorf("error = %q, want %q", errResp.Error, "invalid_request")
	}
}

// ---------------------------------------------------------------------------
// HandleToken: valid PKCE exchange
// ---------------------------------------------------------------------------

func TestHandleToken_ValidPKCE(t *testing.T) {
	t.Parallel()
	s := newTestOAuth2Server()

	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	challenge := computeS256Challenge(verifier)

	s.mu.Lock()
	s.codes["valid-code"] = &AuthCode{
		Code:          "valid-code",
		ClientID:      "test-client",
		RedirectURI:   "http://localhost:8000/callback",
		CodeChallenge: challenge,
		CodeMethod:    "S256",
		Session:       &lastpass.Session{},
	}
	s.mu.Unlock()

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {"valid-code"},
		"client_id":     {"test-client"},
		"code_verifier": {verifier},
	}
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	s.HandleToken(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d; body = %s", w.Code, http.StatusOK, w.Body.String())
	}

	var tokenResp TokenResponse
	_ = json.Unmarshal(w.Body.Bytes(), &tokenResp)
	if tokenResp.AccessToken == "" {
		t.Error("expected non-empty access_token")
	}
	if tokenResp.TokenType != "Bearer" {
		t.Errorf("token_type = %q, want %q", tokenResp.TokenType, "Bearer")
	}
}

// ---------------------------------------------------------------------------
// Metadata: no "none" in token_endpoint_auth_methods_supported
// ---------------------------------------------------------------------------

func TestAuthorizationServerMetadata_NoNoneAuthMethod(t *testing.T) {
	t.Parallel()
	s := newTestOAuth2Server()

	req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-authorization-server", nil)
	w := httptest.NewRecorder()

	s.HandleAuthorizationServerMetadata(w, req)

	var meta AuthorizationServerMetadata
	_ = json.Unmarshal(w.Body.Bytes(), &meta)

	for _, method := range meta.TokenEndpointAuthMethodsSupported {
		if method == "none" {
			t.Error("token_endpoint_auth_methods_supported should not contain 'none'")
		}
	}
}

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

func newTestOAuth2Server() *OAuth2Server {
	return &OAuth2Server{
		baseURL: "http://localhost:8080",
		clients: make(map[string]*RegisteredClient),
		states:  make(map[string]*AuthState),
		codes:   make(map[string]*AuthCode),
		tokens:  make(map[string]*TokenMapping),
	}
}

func registerTestClient(s *OAuth2Server, clientID, redirectURI string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.clients[clientID] = &RegisteredClient{
		ClientID:     clientID,
		ClientSecret: "test-secret",
		RedirectURIs: []string{redirectURI},
	}
}

func computeS256Challenge(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}
