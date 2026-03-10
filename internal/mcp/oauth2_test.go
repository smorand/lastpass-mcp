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
	"time"

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
		{"localhost:8000 deep path", "http://localhost:8000/some/deep/path", true},
		{"production callback exact", "https://lastpass.mcp.scm-platform.org/oauth/callback", true},
		{"localhost wrong port", "http://localhost:9999/callback", false},
		{"localhost port 80 explicit", "http://localhost:80/callback", false},
		{"external domain http", "http://evil.example.com/callback", false},
		{"external domain https", "https://evil.example.com/callback", false},
		{"fragment present", "http://localhost:8000/callback#frag", false},
		{"empty string", "", false},
		{"malformed URI", "://not-a-uri", false},
		{"production with extra path", "https://lastpass.mcp.scm-platform.org/oauth/callback/extra", false},
		{"localhost https wrong scheme", "https://localhost:8000/callback", false},
		{"production http scheme", "http://lastpass.mcp.scm-platform.org/oauth/callback", false},
		{"javascript scheme", "javascript:alert(1)", false},
		{"data scheme", "data:text/html,<script>alert(1)</script>", false},
		{"ftp scheme", "ftp://localhost:8000/callback", false},
		{"localhost no port http", "http://localhost/callback", false},
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
// validatePKCE
// ---------------------------------------------------------------------------

func TestValidatePKCE(t *testing.T) {
	t.Parallel()

	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	challenge := computeS256Challenge(verifier)

	tests := []struct {
		name      string
		verifier  string
		challenge string
		method    string
		want      bool
	}{
		{
			name:      "valid S256 verifier",
			verifier:  verifier,
			challenge: challenge,
			method:    "S256",
			want:      true,
		},
		{
			name:      "valid S256 with empty method (defaults to S256)",
			verifier:  verifier,
			challenge: challenge,
			method:    "",
			want:      true,
		},
		{
			name:      "wrong verifier",
			verifier:  "wrong-verifier-value",
			challenge: challenge,
			method:    "S256",
			want:      false,
		},
		{
			name:      "wrong challenge",
			verifier:  verifier,
			challenge: "wrong-challenge",
			method:    "S256",
			want:      false,
		},
		{
			name:      "unsupported method (plain)",
			verifier:  verifier,
			challenge: verifier,
			method:    "plain",
			want:      false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := validatePKCE(tc.verifier, tc.challenge, tc.method)
			if got != tc.want {
				t.Errorf("validatePKCE() = %v, want %v", got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// generateSecureToken
// ---------------------------------------------------------------------------

func TestGenerateSecureToken(t *testing.T) {
	t.Parallel()

	t.Run("returns non-empty string", func(t *testing.T) {
		t.Parallel()
		token := generateSecureToken(16)
		if token == "" {
			t.Error("expected non-empty token")
		}
	})

	t.Run("different calls produce different tokens", func(t *testing.T) {
		t.Parallel()
		t1 := generateSecureToken(32)
		t2 := generateSecureToken(32)
		if t1 == t2 {
			t.Error("two calls produced identical tokens, randomness may be broken")
		}
	})

	t.Run("different lengths produce different sized output", func(t *testing.T) {
		t.Parallel()
		short := generateSecureToken(8)
		long := generateSecureToken(32)
		if len(short) >= len(long) {
			t.Errorf("expected short token (%d) to be shorter than long token (%d)", len(short), len(long))
		}
	})
}

// ---------------------------------------------------------------------------
// HandleProtectedResourceMetadata
// ---------------------------------------------------------------------------

func TestHandleProtectedResourceMetadata(t *testing.T) {
	t.Parallel()

	t.Run("GET returns valid metadata", func(t *testing.T) {
		t.Parallel()
		s := newTestOAuth2Server()

		req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-protected-resource", nil)
		w := httptest.NewRecorder()
		s.HandleProtectedResourceMetadata(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
		}

		ct := w.Header().Get("Content-Type")
		if ct != "application/json" {
			t.Errorf("Content-Type = %q, want application/json", ct)
		}

		var meta ProtectedResourceMetadata
		if err := json.Unmarshal(w.Body.Bytes(), &meta); err != nil {
			t.Fatalf("failed to parse response: %v", err)
		}

		if meta.Resource != "http://localhost:8080" {
			t.Errorf("resource = %q, want %q", meta.Resource, "http://localhost:8080")
		}
		if len(meta.AuthorizationServers) != 1 || meta.AuthorizationServers[0] != "http://localhost:8080" {
			t.Errorf("authorization_servers = %v, want [%q]", meta.AuthorizationServers, "http://localhost:8080")
		}
		if len(meta.BearerMethodsSupported) != 1 || meta.BearerMethodsSupported[0] != "header" {
			t.Errorf("bearer_methods_supported = %v, want [header]", meta.BearerMethodsSupported)
		}
	})

	t.Run("POST returns method not allowed", func(t *testing.T) {
		t.Parallel()
		s := newTestOAuth2Server()

		req := httptest.NewRequest(http.MethodPost, "/.well-known/oauth-protected-resource", nil)
		w := httptest.NewRecorder()
		s.HandleProtectedResourceMetadata(w, req)

		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("status = %d, want %d", w.Code, http.StatusMethodNotAllowed)
		}
	})
}

// ---------------------------------------------------------------------------
// HandleAuthorizationServerMetadata
// ---------------------------------------------------------------------------

func TestHandleAuthorizationServerMetadata(t *testing.T) {
	t.Parallel()

	t.Run("GET returns valid metadata with all required fields", func(t *testing.T) {
		t.Parallel()
		s := newTestOAuth2Server()

		req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-authorization-server", nil)
		w := httptest.NewRecorder()
		s.HandleAuthorizationServerMetadata(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
		}

		var meta AuthorizationServerMetadata
		if err := json.Unmarshal(w.Body.Bytes(), &meta); err != nil {
			t.Fatalf("failed to parse response: %v", err)
		}

		if meta.Issuer != "http://localhost:8080" {
			t.Errorf("issuer = %q, want %q", meta.Issuer, "http://localhost:8080")
		}
		if meta.AuthorizationEndpoint != "http://localhost:8080/oauth/authorize" {
			t.Errorf("authorization_endpoint = %q", meta.AuthorizationEndpoint)
		}
		if meta.TokenEndpoint != "http://localhost:8080/oauth/token" {
			t.Errorf("token_endpoint = %q", meta.TokenEndpoint)
		}
		if meta.RegistrationEndpoint != "http://localhost:8080/oauth/register" {
			t.Errorf("registration_endpoint = %q", meta.RegistrationEndpoint)
		}

		// Verify only "code" response type
		if len(meta.ResponseTypesSupported) != 1 || meta.ResponseTypesSupported[0] != "code" {
			t.Errorf("response_types_supported = %v", meta.ResponseTypesSupported)
		}

		// Verify S256 is the only PKCE method
		if len(meta.CodeChallengeMethodsSupported) != 1 || meta.CodeChallengeMethodsSupported[0] != "S256" {
			t.Errorf("code_challenge_methods_supported = %v", meta.CodeChallengeMethodsSupported)
		}

		// Verify grant types include both authorization_code and refresh_token
		grantMap := make(map[string]bool)
		for _, g := range meta.GrantTypesSupported {
			grantMap[g] = true
		}
		if !grantMap["authorization_code"] || !grantMap["refresh_token"] {
			t.Errorf("grant_types_supported = %v, missing required types", meta.GrantTypesSupported)
		}
	})

	t.Run("no none in auth methods", func(t *testing.T) {
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
	})

	t.Run("POST returns method not allowed", func(t *testing.T) {
		t.Parallel()
		s := newTestOAuth2Server()

		req := httptest.NewRequest(http.MethodPost, "/.well-known/oauth-authorization-server", nil)
		w := httptest.NewRecorder()
		s.HandleAuthorizationServerMetadata(w, req)

		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("status = %d, want %d", w.Code, http.StatusMethodNotAllowed)
		}
	})
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
			name:       "valid production redirect",
			body:       `{"redirect_uris":["https://lastpass.mcp.scm-platform.org/oauth/callback"],"client_name":"prod"}`,
			wantStatus: http.StatusCreated,
		},
		{
			name:       "multiple valid redirects",
			body:       `{"redirect_uris":["http://localhost:8000/cb","http://localhost:3000/cb"],"client_name":"multi"}`,
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
		{
			name:       "reject missing redirect_uris field",
			body:       `{"client_name":"test"}`,
			wantStatus: http.StatusBadRequest,
			wantError:  "invalid_request",
		},
		{
			name:       "reject invalid JSON",
			body:       `{invalid json`,
			wantStatus: http.StatusBadRequest,
			wantError:  "invalid_request",
		},
		{
			name:       "reject one valid one invalid redirect",
			body:       `{"redirect_uris":["http://localhost:8000/cb","http://evil.com/steal"]}`,
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
			if tc.wantStatus == http.StatusCreated {
				var resp ClientRegistrationResponse
				if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
					t.Fatalf("failed to parse response: %v", err)
				}
				if resp.ClientID == "" {
					t.Error("expected non-empty client_id")
				}
				if resp.ClientSecret == "" {
					t.Error("expected non-empty client_secret")
				}
				if len(resp.RedirectURIs) == 0 {
					t.Error("expected redirect_uris in response")
				}
				if resp.TokenEndpointAuthMethod != "client_secret_basic" {
					t.Errorf("token_endpoint_auth_method = %q, want client_secret_basic", resp.TokenEndpointAuthMethod)
				}
			}
		})
	}

	t.Run("GET returns method not allowed", func(t *testing.T) {
		t.Parallel()
		s := newTestOAuth2Server()

		req := httptest.NewRequest(http.MethodGet, "/oauth/register", nil)
		w := httptest.NewRecorder()
		s.HandleClientRegistration(w, req)

		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("status = %d, want %d", w.Code, http.StatusMethodNotAllowed)
		}
	})

	t.Run("registration stores client in memory", func(t *testing.T) {
		t.Parallel()
		s := newTestOAuth2Server()

		body := `{"redirect_uris":["http://localhost:8000/callback"],"client_name":"test"}`
		req := httptest.NewRequest(http.MethodPost, "/oauth/register", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		s.HandleClientRegistration(w, req)

		var resp ClientRegistrationResponse
		_ = json.Unmarshal(w.Body.Bytes(), &resp)

		s.mu.RLock()
		client, exists := s.clients[resp.ClientID]
		s.mu.RUnlock()

		if !exists {
			t.Fatal("client was not stored after registration")
		}
		if client.ClientSecret != resp.ClientSecret {
			t.Error("stored client secret does not match response")
		}
	})
}

// ---------------------------------------------------------------------------
// HandleAuthorize GET
// ---------------------------------------------------------------------------

func TestHandleAuthorizeGet(t *testing.T) {
	t.Parallel()

	t.Run("success renders login page", func(t *testing.T) {
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
		// Login form should contain the hidden fields
		body := w.Body.String()
		if !strings.Contains(body, "test-client") {
			t.Error("login page does not contain client_id")
		}
		if !strings.Contains(body, "http://localhost:8000/callback") {
			t.Error("login page does not contain redirect_uri")
		}
	})

	t.Run("missing client_id", func(t *testing.T) {
		t.Parallel()
		s := newTestOAuth2Server()

		q := url.Values{
			"redirect_uri":          {"http://localhost:8000/callback"},
			"response_type":         {"code"},
			"code_challenge":        {"challenge"},
			"code_challenge_method": {"S256"},
		}
		req := httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+q.Encode(), nil)
		w := httptest.NewRecorder()

		s.HandleAuthorize(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
		}
	})

	t.Run("missing redirect_uri", func(t *testing.T) {
		t.Parallel()
		s := newTestOAuth2Server()

		q := url.Values{
			"client_id":             {"some-client"},
			"response_type":         {"code"},
			"code_challenge":        {"challenge"},
			"code_challenge_method": {"S256"},
		}
		req := httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+q.Encode(), nil)
		w := httptest.NewRecorder()

		s.HandleAuthorize(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
		}
	})

	t.Run("unsupported response_type", func(t *testing.T) {
		t.Parallel()
		s := newTestOAuth2Server()

		q := url.Values{
			"client_id":     {"some-client"},
			"redirect_uri":  {"http://localhost:8000/callback"},
			"response_type": {"token"},
		}
		req := httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+q.Encode(), nil)
		w := httptest.NewRecorder()

		s.HandleAuthorize(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
		}
		var errResp TokenErrorResponse
		_ = json.Unmarshal(w.Body.Bytes(), &errResp)
		if errResp.Error != "unsupported_response_type" {
			t.Errorf("error = %q, want unsupported_response_type", errResp.Error)
		}
	})

	t.Run("unregistered client", func(t *testing.T) {
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
	})

	t.Run("redirect_uri not registered for client", func(t *testing.T) {
		t.Parallel()
		s := newTestOAuth2Server()
		registerTestClient(s, "test-client", "http://localhost:8000/callback")

		q := url.Values{
			"client_id":             {"test-client"},
			"redirect_uri":          {"http://localhost:3000/other"},
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
	})

	t.Run("missing PKCE code_challenge", func(t *testing.T) {
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
	})

	t.Run("wrong code_challenge_method (plain)", func(t *testing.T) {
		t.Parallel()
		s := newTestOAuth2Server()
		registerTestClient(s, "test-client", "http://localhost:8000/callback")

		q := url.Values{
			"client_id":             {"test-client"},
			"redirect_uri":          {"http://localhost:8000/callback"},
			"response_type":         {"code"},
			"code_challenge":        {"some-challenge"},
			"code_challenge_method": {"plain"},
		}
		req := httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+q.Encode(), nil)
		w := httptest.NewRecorder()

		s.HandleAuthorize(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
		}
	})

	t.Run("stores auth state in memory", func(t *testing.T) {
		t.Parallel()
		s := newTestOAuth2Server()
		registerTestClient(s, "test-client", "http://localhost:8000/callback")

		verifier := "test-verifier-string-that-is-long-enough"
		challenge := computeS256Challenge(verifier)

		q := url.Values{
			"client_id":             {"test-client"},
			"redirect_uri":          {"http://localhost:8000/callback"},
			"response_type":         {"code"},
			"state":                 {"my-state"},
			"code_challenge":        {challenge},
			"code_challenge_method": {"S256"},
		}
		req := httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+q.Encode(), nil)
		w := httptest.NewRecorder()

		s.HandleAuthorize(w, req)

		s.mu.RLock()
		stateCount := len(s.states)
		s.mu.RUnlock()

		if stateCount != 1 {
			t.Errorf("expected 1 auth state, got %d", stateCount)
		}
	})

	t.Run("unsupported method (PUT)", func(t *testing.T) {
		t.Parallel()
		s := newTestOAuth2Server()

		req := httptest.NewRequest(http.MethodPut, "/oauth/authorize", nil)
		w := httptest.NewRecorder()

		s.HandleAuthorize(w, req)

		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("status = %d, want %d", w.Code, http.StatusMethodNotAllowed)
		}
	})
}

// ---------------------------------------------------------------------------
// HandleAuthorize POST (without real LastPass API)
// ---------------------------------------------------------------------------

func TestHandleAuthorizePost(t *testing.T) {
	t.Parallel()

	t.Run("invalid or expired state", func(t *testing.T) {
		t.Parallel()
		s := newTestOAuth2Server()

		form := url.Values{
			"client_id":             {"test-client"},
			"redirect_uri":          {"http://localhost:8000/callback"},
			"state":                 {"nonexistent-state"},
			"code_challenge":        {"challenge"},
			"code_challenge_method": {"S256"},
			"email":                 {"user@example.com"},
			"password":              {"password123"},
		}
		req := httptest.NewRequest(http.MethodPost, "/oauth/authorize", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()

		s.HandleAuthorize(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
		}
	})

	t.Run("empty email and password re-renders login with error", func(t *testing.T) {
		t.Parallel()
		s := newTestOAuth2Server()

		// Plant an auth state
		s.mu.Lock()
		s.states["test-state"] = &AuthState{
			ClientID:      "test-client",
			RedirectURI:   "http://localhost:8000/callback",
			State:         "client-state",
			CodeChallenge: "challenge",
			CodeMethod:    "S256",
			CreatedAt:     time.Now(),
		}
		s.mu.Unlock()

		form := url.Values{
			"client_id":             {"test-client"},
			"redirect_uri":          {"http://localhost:8000/callback"},
			"state":                 {"test-state"},
			"code_challenge":        {"challenge"},
			"code_challenge_method": {"S256"},
			"email":                 {""},
			"password":              {""},
		}
		req := httptest.NewRequest(http.MethodPost, "/oauth/authorize", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()

		s.HandleAuthorize(w, req)

		// Should re-render the login page with an error (200 with HTML)
		if w.Code != http.StatusOK {
			t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
		}
		body := w.Body.String()
		if !strings.Contains(body, "Email and master password are required") {
			t.Error("expected error message in re-rendered login page")
		}
	})
}

// ---------------------------------------------------------------------------
// HandleToken: authorization_code grant
// ---------------------------------------------------------------------------

func TestHandleToken_AuthorizationCodeGrant(t *testing.T) {
	t.Parallel()

	t.Run("valid PKCE exchange returns tokens", func(t *testing.T) {
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
			Session:       &lastpass.Session{Email: "user@example.com"},
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
			t.Fatalf("status = %d, want %d; body = %s", w.Code, http.StatusOK, w.Body.String())
		}

		var tokenResp TokenResponse
		_ = json.Unmarshal(w.Body.Bytes(), &tokenResp)
		if tokenResp.AccessToken == "" {
			t.Error("expected non-empty access_token")
		}
		if tokenResp.RefreshToken == "" {
			t.Error("expected non-empty refresh_token")
		}
		if tokenResp.TokenType != "Bearer" {
			t.Errorf("token_type = %q, want Bearer", tokenResp.TokenType)
		}
		if tokenResp.ExpiresIn != 86400 {
			t.Errorf("expires_in = %d, want 86400", tokenResp.ExpiresIn)
		}
		if tokenResp.Scope != "vault:read vault:write" {
			t.Errorf("scope = %q, want vault:read vault:write", tokenResp.Scope)
		}
	})

	t.Run("code is single use", func(t *testing.T) {
		t.Parallel()
		s := newTestOAuth2Server()

		verifier := "single-use-test-verifier-long-enough"
		challenge := computeS256Challenge(verifier)

		s.mu.Lock()
		s.codes["one-time-code"] = &AuthCode{
			Code:          "one-time-code",
			ClientID:      "test-client",
			CodeChallenge: challenge,
			CodeMethod:    "S256",
			Session:       &lastpass.Session{},
		}
		s.mu.Unlock()

		form := url.Values{
			"grant_type":    {"authorization_code"},
			"code":          {"one-time-code"},
			"client_id":     {"test-client"},
			"code_verifier": {verifier},
		}

		// First exchange should succeed
		req1 := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
		req1.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w1 := httptest.NewRecorder()
		s.HandleToken(w1, req1)

		if w1.Code != http.StatusOK {
			t.Fatalf("first exchange: status = %d, want %d", w1.Code, http.StatusOK)
		}

		// Second exchange should fail (code consumed)
		req2 := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
		req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w2 := httptest.NewRecorder()
		s.HandleToken(w2, req2)

		if w2.Code != http.StatusBadRequest {
			t.Errorf("second exchange: status = %d, want %d", w2.Code, http.StatusBadRequest)
		}
		var errResp TokenErrorResponse
		_ = json.Unmarshal(w2.Body.Bytes(), &errResp)
		if errResp.Error != "invalid_grant" {
			t.Errorf("error = %q, want invalid_grant", errResp.Error)
		}
	})

	t.Run("missing code returns error", func(t *testing.T) {
		t.Parallel()
		s := newTestOAuth2Server()

		form := url.Values{
			"grant_type":    {"authorization_code"},
			"client_id":     {"test-client"},
			"code_verifier": {"some-verifier"},
		}
		req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()

		s.HandleToken(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
		}
	})

	t.Run("PKCE required (missing code_verifier)", func(t *testing.T) {
		t.Parallel()
		s := newTestOAuth2Server()

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
			t.Errorf("error = %q, want invalid_request", errResp.Error)
		}
	})

	t.Run("wrong code_verifier fails PKCE", func(t *testing.T) {
		t.Parallel()
		s := newTestOAuth2Server()

		verifier := "correct-verifier-long-enough"
		challenge := computeS256Challenge(verifier)

		s.mu.Lock()
		s.codes["pkce-code"] = &AuthCode{
			Code:          "pkce-code",
			ClientID:      "test-client",
			CodeChallenge: challenge,
			CodeMethod:    "S256",
			Session:       &lastpass.Session{},
		}
		s.mu.Unlock()

		form := url.Values{
			"grant_type":    {"authorization_code"},
			"code":          {"pkce-code"},
			"client_id":     {"test-client"},
			"code_verifier": {"wrong-verifier-completely"},
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
		if errResp.Error != "invalid_grant" {
			t.Errorf("error = %q, want invalid_grant", errResp.Error)
		}
	})

	t.Run("client_id mismatch", func(t *testing.T) {
		t.Parallel()
		s := newTestOAuth2Server()

		verifier := "mismatch-test-verifier"
		challenge := computeS256Challenge(verifier)

		s.mu.Lock()
		s.codes["mismatch-code"] = &AuthCode{
			Code:          "mismatch-code",
			ClientID:      "real-client",
			CodeChallenge: challenge,
			CodeMethod:    "S256",
			Session:       &lastpass.Session{},
		}
		s.mu.Unlock()

		form := url.Values{
			"grant_type":    {"authorization_code"},
			"code":          {"mismatch-code"},
			"client_id":     {"different-client"},
			"code_verifier": {verifier},
		}
		req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()

		s.HandleToken(w, req)

		if w.Code != http.StatusUnauthorized {
			t.Errorf("status = %d, want %d", w.Code, http.StatusUnauthorized)
		}
	})

	t.Run("client_id from Basic auth header", func(t *testing.T) {
		t.Parallel()
		s := newTestOAuth2Server()

		verifier := "basic-auth-verifier-long-enough"
		challenge := computeS256Challenge(verifier)

		s.mu.Lock()
		s.codes["basic-code"] = &AuthCode{
			Code:          "basic-code",
			ClientID:      "basic-client",
			CodeChallenge: challenge,
			CodeMethod:    "S256",
			Session:       &lastpass.Session{},
		}
		s.mu.Unlock()

		form := url.Values{
			"grant_type":    {"authorization_code"},
			"code":          {"basic-code"},
			"code_verifier": {verifier},
		}
		req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth("basic-client", "secret")
		w := httptest.NewRecorder()

		s.HandleToken(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("status = %d, want %d; body = %s", w.Code, http.StatusOK, w.Body.String())
		}
	})

	t.Run("token mapped to session after exchange", func(t *testing.T) {
		t.Parallel()
		s := newTestOAuth2Server()

		verifier := "session-check-verifier-long"
		challenge := computeS256Challenge(verifier)
		testSession := &lastpass.Session{
			Email:     "test@lp.com",
			SessionID: "sess123",
		}

		s.mu.Lock()
		s.codes["session-code"] = &AuthCode{
			Code:          "session-code",
			ClientID:      "test-client",
			CodeChallenge: challenge,
			CodeMethod:    "S256",
			Session:       testSession,
		}
		s.mu.Unlock()

		form := url.Values{
			"grant_type":    {"authorization_code"},
			"code":          {"session-code"},
			"client_id":     {"test-client"},
			"code_verifier": {verifier},
		}
		req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()

		s.HandleToken(w, req)

		var tokenResp TokenResponse
		_ = json.Unmarshal(w.Body.Bytes(), &tokenResp)

		// Validate the token maps to the session
		session, err := s.ValidateAccessToken(tokenResp.AccessToken)
		if err != nil {
			t.Fatalf("ValidateAccessToken failed: %v", err)
		}
		if session.Email != "test@lp.com" {
			t.Errorf("session email = %q, want test@lp.com", session.Email)
		}
	})
}

// ---------------------------------------------------------------------------
// HandleToken: refresh_token grant
// ---------------------------------------------------------------------------

func TestHandleToken_RefreshTokenGrant(t *testing.T) {
	t.Parallel()

	t.Run("valid refresh token rotates tokens", func(t *testing.T) {
		t.Parallel()
		s := newTestOAuth2Server()

		testSession := &lastpass.Session{Email: "refresh@test.com"}
		oldMapping := &TokenMapping{
			BearerToken: "old-bearer",
			Session:     testSession,
			ClientID:    "test-client",
			CreatedAt:   time.Now(),
		}

		s.mu.Lock()
		s.tokens["old-refresh"] = oldMapping
		s.mu.Unlock()

		form := url.Values{
			"grant_type":    {"refresh_token"},
			"refresh_token": {"old-refresh"},
			"client_id":     {"test-client"},
		}
		req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()

		s.HandleToken(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, want %d; body = %s", w.Code, http.StatusOK, w.Body.String())
		}

		var tokenResp TokenResponse
		_ = json.Unmarshal(w.Body.Bytes(), &tokenResp)

		if tokenResp.AccessToken == "" {
			t.Error("expected non-empty new access_token")
		}
		if tokenResp.RefreshToken == "" {
			t.Error("expected non-empty new refresh_token")
		}
		if tokenResp.TokenType != "Bearer" {
			t.Errorf("token_type = %q, want Bearer", tokenResp.TokenType)
		}

		// Old refresh token should be invalidated
		s.mu.RLock()
		_, oldExists := s.tokens["old-refresh"]
		s.mu.RUnlock()
		if oldExists {
			t.Error("old refresh token should have been removed")
		}

		// New token should map to the same session
		session, err := s.ValidateAccessToken(tokenResp.AccessToken)
		if err != nil {
			t.Fatalf("new token validation failed: %v", err)
		}
		if session.Email != "refresh@test.com" {
			t.Errorf("session email = %q, want refresh@test.com", session.Email)
		}
	})

	t.Run("missing refresh_token", func(t *testing.T) {
		t.Parallel()
		s := newTestOAuth2Server()

		form := url.Values{
			"grant_type": {"refresh_token"},
			"client_id":  {"test-client"},
		}
		req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()

		s.HandleToken(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
		}
	})

	t.Run("invalid refresh_token", func(t *testing.T) {
		t.Parallel()
		s := newTestOAuth2Server()

		form := url.Values{
			"grant_type":    {"refresh_token"},
			"refresh_token": {"nonexistent-token"},
			"client_id":     {"test-client"},
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
		if errResp.Error != "invalid_grant" {
			t.Errorf("error = %q, want invalid_grant", errResp.Error)
		}
	})

	t.Run("refresh token with nil session fails", func(t *testing.T) {
		t.Parallel()
		s := newTestOAuth2Server()

		s.mu.Lock()
		s.tokens["nil-session-refresh"] = &TokenMapping{
			BearerToken: "some-bearer",
			Session:     nil,
			ClientID:    "test-client",
		}
		s.mu.Unlock()

		form := url.Values{
			"grant_type":    {"refresh_token"},
			"refresh_token": {"nil-session-refresh"},
			"client_id":     {"test-client"},
		}
		req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()

		s.HandleToken(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
		}
	})
}

// ---------------------------------------------------------------------------
// HandleToken: unsupported grant type
// ---------------------------------------------------------------------------

func TestHandleToken_UnsupportedGrantType(t *testing.T) {
	t.Parallel()
	s := newTestOAuth2Server()

	form := url.Values{
		"grant_type": {"client_credentials"},
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
	if errResp.Error != "unsupported_grant_type" {
		t.Errorf("error = %q, want unsupported_grant_type", errResp.Error)
	}
}

func TestHandleToken_MethodNotAllowed(t *testing.T) {
	t.Parallel()
	s := newTestOAuth2Server()

	req := httptest.NewRequest(http.MethodGet, "/oauth/token", nil)
	w := httptest.NewRecorder()

	s.HandleToken(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want %d", w.Code, http.StatusMethodNotAllowed)
	}
}

// ---------------------------------------------------------------------------
// ValidateAccessToken
// ---------------------------------------------------------------------------

func TestValidateAccessToken(t *testing.T) {
	t.Parallel()

	t.Run("valid token returns session", func(t *testing.T) {
		t.Parallel()
		s := newTestOAuth2Server()

		testSession := &lastpass.Session{Email: "validate@test.com"}
		s.mu.Lock()
		s.tokens["valid-bearer"] = &TokenMapping{
			BearerToken: "valid-bearer",
			Session:     testSession,
			ClientID:    "test-client",
		}
		s.mu.Unlock()

		session, err := s.ValidateAccessToken("valid-bearer")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if session.Email != "validate@test.com" {
			t.Errorf("email = %q, want validate@test.com", session.Email)
		}
	})

	t.Run("unknown token returns error", func(t *testing.T) {
		t.Parallel()
		s := newTestOAuth2Server()

		_, err := s.ValidateAccessToken("nonexistent")
		if err == nil {
			t.Error("expected error for nonexistent token")
		}
	})

	t.Run("token with nil session returns error", func(t *testing.T) {
		t.Parallel()
		s := newTestOAuth2Server()

		s.mu.Lock()
		s.tokens["nil-session"] = &TokenMapping{
			BearerToken: "nil-session",
			Session:     nil,
		}
		s.mu.Unlock()

		_, err := s.ValidateAccessToken("nil-session")
		if err == nil {
			t.Error("expected error for nil session")
		}
	})
}

// ---------------------------------------------------------------------------
// InvalidateToken
// ---------------------------------------------------------------------------

func TestInvalidateToken(t *testing.T) {
	t.Parallel()

	s := newTestOAuth2Server()
	s.mu.Lock()
	s.tokens["to-invalidate"] = &TokenMapping{
		BearerToken: "to-invalidate",
		Session:     &lastpass.Session{},
	}
	s.mu.Unlock()

	s.InvalidateToken("to-invalidate")

	_, err := s.ValidateAccessToken("to-invalidate")
	if err == nil {
		t.Error("expected error after token invalidation")
	}
}

// ---------------------------------------------------------------------------
// StoreTokenSession
// ---------------------------------------------------------------------------

func TestStoreTokenSession(t *testing.T) {
	t.Parallel()

	t.Run("updates session for existing token", func(t *testing.T) {
		t.Parallel()
		s := newTestOAuth2Server()

		oldSession := &lastpass.Session{Email: "old@test.com"}
		s.mu.Lock()
		s.tokens["update-token"] = &TokenMapping{
			BearerToken: "update-token",
			Session:     oldSession,
		}
		s.mu.Unlock()

		newSession := &lastpass.Session{Email: "new@test.com"}
		s.StoreTokenSession("update-token", newSession)

		session, err := s.ValidateAccessToken("update-token")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if session.Email != "new@test.com" {
			t.Errorf("email = %q, want new@test.com", session.Email)
		}
	})

	t.Run("no-op for nonexistent token", func(t *testing.T) {
		t.Parallel()
		s := newTestOAuth2Server()

		// Should not panic
		s.StoreTokenSession("nonexistent", &lastpass.Session{})

		s.mu.RLock()
		tokenCount := len(s.tokens)
		s.mu.RUnlock()

		if tokenCount != 0 {
			t.Errorf("expected 0 tokens, got %d", tokenCount)
		}
	})
}

// ---------------------------------------------------------------------------
// writeOAuthError
// ---------------------------------------------------------------------------

func TestWriteOAuthError(t *testing.T) {
	t.Parallel()

	w := httptest.NewRecorder()
	writeOAuthError(w, "invalid_request", "Missing parameter", http.StatusBadRequest)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}

	ct := w.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}

	var errResp TokenErrorResponse
	if err := json.Unmarshal(w.Body.Bytes(), &errResp); err != nil {
		t.Fatalf("failed to parse error response: %v", err)
	}
	if errResp.Error != "invalid_request" {
		t.Errorf("error = %q, want invalid_request", errResp.Error)
	}
	if errResp.ErrorDescription != "Missing parameter" {
		t.Errorf("error_description = %q, want Missing parameter", errResp.ErrorDescription)
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
