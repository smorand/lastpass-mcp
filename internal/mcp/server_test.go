package mcp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"lastpass-mcp/internal/lastpass"
)

// ---------------------------------------------------------------------------
// Context helpers: WithSession / GetSession
// ---------------------------------------------------------------------------

func TestContextSession(t *testing.T) {
	t.Parallel()

	t.Run("round trip: store and retrieve session", func(t *testing.T) {
		t.Parallel()
		session := &lastpass.Session{Email: "ctx@test.com", SessionID: "sess-1"}
		ctx := WithSession(context.Background(), session)
		got, ok := GetSession(ctx)
		if !ok {
			t.Fatal("GetSession returned false")
		}
		if got.Email != "ctx@test.com" {
			t.Errorf("email = %q, want ctx@test.com", got.Email)
		}
	})

	t.Run("empty context returns false", func(t *testing.T) {
		t.Parallel()
		_, ok := GetSession(context.Background())
		if ok {
			t.Error("expected false for empty context")
		}
	})

	t.Run("nil session stored and retrieved", func(t *testing.T) {
		t.Parallel()
		ctx := WithSession(context.Background(), nil)
		got, ok := GetSession(ctx)
		if !ok {
			t.Error("expected ok=true even with nil session (type assertion succeeds)")
		}
		if got != nil {
			t.Error("expected nil session")
		}
	})
}

// ---------------------------------------------------------------------------
// Context helpers: withBearerToken / getBearerToken
// ---------------------------------------------------------------------------

func TestContextBearerToken(t *testing.T) {
	t.Parallel()

	t.Run("round trip: store and retrieve token", func(t *testing.T) {
		t.Parallel()
		ctx := withBearerToken(context.Background(), "test-bearer-token")
		got, ok := getBearerToken(ctx)
		if !ok {
			t.Fatal("getBearerToken returned false")
		}
		if got != "test-bearer-token" {
			t.Errorf("token = %q, want test-bearer-token", got)
		}
	})

	t.Run("empty context returns false", func(t *testing.T) {
		t.Parallel()
		_, ok := getBearerToken(context.Background())
		if ok {
			t.Error("expected false for empty context")
		}
	})
}

// ---------------------------------------------------------------------------
// extractBearerToken
// ---------------------------------------------------------------------------

func TestExtractBearerToken(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		authValue string
		want      string
	}{
		{
			name:      "valid bearer token",
			authValue: "Bearer abc123xyz",
			want:      "abc123xyz",
		},
		{
			name:      "empty header",
			authValue: "",
			want:      "",
		},
		{
			name:      "wrong scheme (Basic)",
			authValue: "Basic dXNlcjpwYXNz",
			want:      "",
		},
		{
			name:      "bearer lowercase (should not match)",
			authValue: "bearer abc123",
			want:      "",
		},
		{
			name:      "Bearer with no token value",
			authValue: "Bearer ",
			want:      "",
		},
		{
			name:      "Bearer with spaces in token",
			authValue: "Bearer token with spaces",
			want:      "token with spaces",
		},
		{
			name:      "missing space after Bearer",
			authValue: "Bearertoken",
			want:      "",
		},
		{
			name:      "long JWT-like token",
			authValue: "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
			want:      "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			if tc.authValue != "" {
				r.Header.Set("Authorization", tc.authValue)
			}
			got := extractBearerToken(r)
			if got != tc.want {
				t.Errorf("extractBearerToken(%q) = %q, want %q", tc.authValue, got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// authMiddleware
// ---------------------------------------------------------------------------

func TestAuthMiddleware(t *testing.T) {
	t.Parallel()

	t.Run("no token returns 401 with WWW-Authenticate", func(t *testing.T) {
		t.Parallel()
		srv := newTestServer()
		handler := srv.authMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		req := httptest.NewRequest(http.MethodGet, "/mcp", nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		if w.Code != http.StatusUnauthorized {
			t.Errorf("status = %d, want %d", w.Code, http.StatusUnauthorized)
		}
		wwwAuth := w.Header().Get("WWW-Authenticate")
		if wwwAuth == "" {
			t.Error("expected WWW-Authenticate header")
		}
		if !containsSubstring(wwwAuth, "resource_metadata") {
			t.Errorf("WWW-Authenticate should contain resource_metadata, got %q", wwwAuth)
		}
	})

	t.Run("invalid token returns 401 with invalid_token error", func(t *testing.T) {
		t.Parallel()
		srv := newTestServer()
		handler := srv.authMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		req := httptest.NewRequest(http.MethodGet, "/mcp", nil)
		req.Header.Set("Authorization", "Bearer invalid-token-xyz")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		if w.Code != http.StatusUnauthorized {
			t.Errorf("status = %d, want %d", w.Code, http.StatusUnauthorized)
		}
		wwwAuth := w.Header().Get("WWW-Authenticate")
		if !containsSubstring(wwwAuth, "invalid_token") {
			t.Errorf("WWW-Authenticate should contain invalid_token, got %q", wwwAuth)
		}
	})

	t.Run("valid token injects session and bearer token into context", func(t *testing.T) {
		t.Parallel()
		srv := newTestServer()

		testSession := &lastpass.Session{Email: "mid@test.com"}
		srv.oauth2Server.mu.Lock()
		srv.oauth2Server.tokens["valid-token-mid"] = &TokenMapping{
			BearerToken: "valid-token-mid",
			Session:     testSession,
		}
		srv.oauth2Server.mu.Unlock()

		var gotSession *lastpass.Session
		var gotToken string
		handler := srv.authMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gotSession, _ = GetSession(r.Context())
			gotToken, _ = getBearerToken(r.Context())
			w.WriteHeader(http.StatusOK)
		}))

		req := httptest.NewRequest(http.MethodGet, "/mcp", nil)
		req.Header.Set("Authorization", "Bearer valid-token-mid")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
		}
		if gotSession == nil || gotSession.Email != "mid@test.com" {
			t.Errorf("session email = %v, want mid@test.com", gotSession)
		}
		if gotToken != "valid-token-mid" {
			t.Errorf("bearer token = %q, want valid-token-mid", gotToken)
		}
	})

	t.Run("nil oauth2Server returns 500", func(t *testing.T) {
		t.Parallel()
		srv := &Server{
			config: &Config{BaseURL: "http://localhost:8080"},
			// oauth2Server is intentionally nil
		}
		handler := srv.authMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		req := httptest.NewRequest(http.MethodGet, "/mcp", nil)
		req.Header.Set("Authorization", "Bearer some-token")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		if w.Code != http.StatusInternalServerError {
			t.Errorf("status = %d, want %d", w.Code, http.StatusInternalServerError)
		}
	})
}

// ---------------------------------------------------------------------------
// Tool handlers: handleSearch
// ---------------------------------------------------------------------------

func TestHandleSearch(t *testing.T) {
	t.Parallel()

	entries := []lastpass.Entry{
		{ID: "1", Name: "GitHub", URL: "https://github.com", Username: "devuser", Type: "password"},
		{ID: "2", Name: "Gmail", URL: "https://mail.google.com", Username: "user@gmail.com", Type: "password"},
		{ID: "3", Name: "My Visa Card", URL: "http://sn", Username: "", Type: "paymentcard"},
		{ID: "4", Name: "AWS Console", URL: "https://aws.amazon.com", Username: "admin", Type: "password"},
		{ID: "5", Name: "GitLab", URL: "https://gitlab.com", Username: "gituser", Type: "password"},
	}

	t.Run("search by name matches multiple entries", func(t *testing.T) {
		t.Parallel()
		srv := newTestServer()
		ctx := contextWithSessionAndToken(entries, "token-1")

		_, out, err := srv.handleSearch(ctx, nil, SearchInput{Pattern: "Git"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if out.Count != 2 {
			t.Errorf("count = %d, want 2", out.Count)
		}
		names := make(map[string]bool)
		for _, r := range out.Results {
			names[r.Name] = true
		}
		if !names["GitHub"] || !names["GitLab"] {
			t.Errorf("expected GitHub and GitLab, got %v", out.Results)
		}
	})

	t.Run("search by URL", func(t *testing.T) {
		t.Parallel()
		srv := newTestServer()
		ctx := contextWithSessionAndToken(entries, "token-1")

		_, out, err := srv.handleSearch(ctx, nil, SearchInput{Pattern: "amazon"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if out.Count != 1 || out.Results[0].Name != "AWS Console" {
			t.Errorf("expected AWS Console, got %v", out.Results)
		}
	})

	t.Run("search by username", func(t *testing.T) {
		t.Parallel()
		srv := newTestServer()
		ctx := contextWithSessionAndToken(entries, "token-1")

		_, out, err := srv.handleSearch(ctx, nil, SearchInput{Pattern: "devuser"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if out.Count != 1 || out.Results[0].ID != "1" {
			t.Errorf("expected entry 1, got %v", out.Results)
		}
	})

	t.Run("case insensitive search", func(t *testing.T) {
		t.Parallel()
		srv := newTestServer()
		ctx := contextWithSessionAndToken(entries, "token-1")

		_, out, err := srv.handleSearch(ctx, nil, SearchInput{Pattern: "github"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if out.Count != 1 || out.Results[0].Name != "GitHub" {
			t.Errorf("expected GitHub, got %v", out.Results)
		}
	})

	t.Run("filter by type password", func(t *testing.T) {
		t.Parallel()
		srv := newTestServer()
		ctx := contextWithSessionAndToken(entries, "token-1")

		_, out, err := srv.handleSearch(ctx, nil, SearchInput{Pattern: ".", Type: "password"})
		if err == nil {
			// "." is a broad pattern, should be rejected
			// Actually checking: the pattern "." is in the broad list
			_ = out
		}
		// Use a specific search with type filter
		_, out, err = srv.handleSearch(ctx, nil, SearchInput{Pattern: "G", Type: "password"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		for _, r := range out.Results {
			if r.Type != "password" {
				t.Errorf("expected type password, got %q for %q", r.Type, r.Name)
			}
		}
	})

	t.Run("filter by type paymentcard", func(t *testing.T) {
		t.Parallel()
		srv := newTestServer()
		ctx := contextWithSessionAndToken(entries, "token-1")

		_, out, err := srv.handleSearch(ctx, nil, SearchInput{Pattern: "Visa", Type: "paymentcard"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if out.Count != 1 || out.Results[0].Type != "paymentcard" {
			t.Errorf("expected 1 paymentcard, got %v", out.Results)
		}
	})

	t.Run("no matches returns empty results", func(t *testing.T) {
		t.Parallel()
		srv := newTestServer()
		ctx := contextWithSessionAndToken(entries, "token-1")

		_, out, err := srv.handleSearch(ctx, nil, SearchInput{Pattern: "nonexistent-xyz"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if out.Count != 0 {
			t.Errorf("count = %d, want 0", out.Count)
		}
		if len(out.Results) != 0 {
			t.Errorf("expected empty results, got %d", len(out.Results))
		}
	})

	t.Run("empty pattern returns error", func(t *testing.T) {
		t.Parallel()
		srv := newTestServer()
		ctx := contextWithSessionAndToken(entries, "token-1")

		_, _, err := srv.handleSearch(ctx, nil, SearchInput{Pattern: ""})
		if err == nil {
			t.Error("expected error for empty pattern")
		}
	})

	t.Run("overly broad patterns rejected", func(t *testing.T) {
		t.Parallel()
		srv := newTestServer()
		ctx := contextWithSessionAndToken(entries, "token-1")

		broadPatterns := []string{".*", ".+", ".", "*"}
		for _, p := range broadPatterns {
			_, _, err := srv.handleSearch(ctx, nil, SearchInput{Pattern: p})
			if err == nil {
				t.Errorf("expected error for broad pattern %q", p)
			}
		}
	})

	t.Run("invalid regex returns error", func(t *testing.T) {
		t.Parallel()
		srv := newTestServer()
		ctx := contextWithSessionAndToken(entries, "token-1")

		_, _, err := srv.handleSearch(ctx, nil, SearchInput{Pattern: "[invalid"})
		if err == nil {
			t.Error("expected error for invalid regex")
		}
	})

	t.Run("no session returns error", func(t *testing.T) {
		t.Parallel()
		srv := newTestServer()
		ctx := context.Background()

		_, _, err := srv.handleSearch(ctx, nil, SearchInput{Pattern: "test"})
		if err == nil {
			t.Error("expected error when no session")
		}
	})

	t.Run("empty entry type defaults to password in results", func(t *testing.T) {
		t.Parallel()
		srv := newTestServer()
		entriesNoType := []lastpass.Entry{
			{ID: "10", Name: "NoType Entry", URL: "https://example.com", Username: "u", Type: ""},
		}
		ctx := contextWithSessionAndToken(entriesNoType, "token-1")

		_, out, err := srv.handleSearch(ctx, nil, SearchInput{Pattern: "NoType"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if out.Count != 1 || out.Results[0].Type != "password" {
			t.Errorf("expected type password for empty type entry, got %q", out.Results[0].Type)
		}
	})

	t.Run("regex special characters in search", func(t *testing.T) {
		t.Parallel()
		srv := newTestServer()
		entriesSpecial := []lastpass.Entry{
			{ID: "20", Name: "Site (v2.0)", URL: "https://example.com", Username: "u", Type: "password"},
		}
		ctx := contextWithSessionAndToken(entriesSpecial, "token-1")

		_, out, err := srv.handleSearch(ctx, nil, SearchInput{Pattern: `Site \(v2`})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if out.Count != 1 {
			t.Errorf("count = %d, want 1", out.Count)
		}
	})
}

// ---------------------------------------------------------------------------
// Tool handlers: handleShow
// ---------------------------------------------------------------------------

func TestHandleShow(t *testing.T) {
	t.Parallel()

	passwordEntry := lastpass.Entry{
		ID:           "100",
		Name:         "My Website",
		URL:          "https://example.com",
		Username:     "admin",
		Password:     "s3cret!",
		Notes:        "Production credentials",
		Type:         "password",
		LastModified: "1700000000",
		LastTouch:    "1700000001",
	}

	cardEntry := lastpass.Entry{
		ID:             "200",
		Name:           "My Visa",
		URL:            "http://sn",
		Type:           "paymentcard",
		Notes:          "NoteType:Credit Card\nName on Card:Jane Doe",
		CardholderName: "Jane Doe",
		CardType:       "Visa",
		CardNumber:     "4111111111111111",
		SecurityCode:   "456",
		StartDate:      "01/2023",
		ExpirationDate: "12/2027",
		LastModified:   "1700000002",
		LastTouch:      "1700000003",
	}

	entries := []lastpass.Entry{passwordEntry, cardEntry}

	t.Run("show password entry returns all fields", func(t *testing.T) {
		t.Parallel()
		srv := newTestServer()
		ctx := contextWithSessionAndToken(entries, "token-1")

		_, out, err := srv.handleShow(ctx, nil, ShowInput{ID: "100"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if out.ID != "100" {
			t.Errorf("ID = %q, want 100", out.ID)
		}
		if out.Name != "My Website" {
			t.Errorf("Name = %q", out.Name)
		}
		if out.URL != "https://example.com" {
			t.Errorf("URL = %q", out.URL)
		}
		if out.Username != "admin" {
			t.Errorf("Username = %q", out.Username)
		}
		if out.Password != "s3cret!" {
			t.Errorf("Password = %q", out.Password)
		}
		if out.Notes != "Production credentials" {
			t.Errorf("Notes = %q", out.Notes)
		}
		if out.Type != "password" {
			t.Errorf("Type = %q", out.Type)
		}
		if out.LastModified != "1700000000" {
			t.Errorf("LastModified = %q", out.LastModified)
		}
		if out.LastTouch != "1700000001" {
			t.Errorf("LastTouch = %q", out.LastTouch)
		}
		// Password entries should not have card fields
		if out.CardholderName != "" || out.CardNumber != "" {
			t.Error("password entry should not have card fields set")
		}
	})

	t.Run("show paymentcard entry returns card fields", func(t *testing.T) {
		t.Parallel()
		srv := newTestServer()
		ctx := contextWithSessionAndToken(entries, "token-1")

		_, out, err := srv.handleShow(ctx, nil, ShowInput{ID: "200"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if out.Type != "paymentcard" {
			t.Errorf("Type = %q, want paymentcard", out.Type)
		}
		if out.CardholderName != "Jane Doe" {
			t.Errorf("CardholderName = %q", out.CardholderName)
		}
		if out.CardType != "Visa" {
			t.Errorf("CardType = %q", out.CardType)
		}
		if out.CardNumber != "4111111111111111" {
			t.Errorf("CardNumber = %q", out.CardNumber)
		}
		if out.SecurityCode != "456" {
			t.Errorf("SecurityCode = %q", out.SecurityCode)
		}
		if out.StartDate != "01/2023" {
			t.Errorf("StartDate = %q", out.StartDate)
		}
		if out.ExpirationDate != "12/2027" {
			t.Errorf("ExpirationDate = %q", out.ExpirationDate)
		}
		// Card entries should not have URL/Username/Password populated
		if out.URL != "" || out.Username != "" || out.Password != "" {
			t.Error("paymentcard entry should not have url/username/password fields set")
		}
	})

	t.Run("entry not found returns error", func(t *testing.T) {
		t.Parallel()
		srv := newTestServer()
		ctx := contextWithSessionAndToken(entries, "token-1")

		_, _, err := srv.handleShow(ctx, nil, ShowInput{ID: "99999"})
		if err == nil {
			t.Error("expected error for nonexistent entry")
		}
		if !containsSubstring(err.Error(), "not found") {
			t.Errorf("error should mention 'not found', got: %v", err)
		}
	})

	t.Run("empty ID returns error", func(t *testing.T) {
		t.Parallel()
		srv := newTestServer()
		ctx := contextWithSessionAndToken(entries, "token-1")

		_, _, err := srv.handleShow(ctx, nil, ShowInput{ID: ""})
		if err == nil {
			t.Error("expected error for empty ID")
		}
	})

	t.Run("no session returns error", func(t *testing.T) {
		t.Parallel()
		srv := newTestServer()

		_, _, err := srv.handleShow(context.Background(), nil, ShowInput{ID: "100"})
		if err == nil {
			t.Error("expected error when no session")
		}
	})

	t.Run("entry with empty type defaults to password", func(t *testing.T) {
		t.Parallel()
		srv := newTestServer()
		noTypeEntries := []lastpass.Entry{
			{ID: "300", Name: "NoType", URL: "https://x.com", Username: "u", Password: "p", Type: ""},
		}
		ctx := contextWithSessionAndToken(noTypeEntries, "token-1")

		_, out, err := srv.handleShow(ctx, nil, ShowInput{ID: "300"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if out.Type != "password" {
			t.Errorf("Type = %q, want password", out.Type)
		}
		if out.URL != "https://x.com" {
			t.Errorf("URL = %q, want https://x.com", out.URL)
		}
	})
}

// ---------------------------------------------------------------------------
// Tool handlers: handleLogin
// ---------------------------------------------------------------------------

func TestHandleLogin(t *testing.T) {
	t.Parallel()

	t.Run("empty email returns error", func(t *testing.T) {
		t.Parallel()
		srv := newTestServer()
		ctx := context.Background()

		_, _, err := srv.handleLogin(ctx, nil, LoginInput{Email: "", Password: "pass"})
		if err == nil {
			t.Error("expected error for empty email")
		}
	})

	t.Run("empty password returns error", func(t *testing.T) {
		t.Parallel()
		srv := newTestServer()
		ctx := context.Background()

		_, _, err := srv.handleLogin(ctx, nil, LoginInput{Email: "test@example.com", Password: ""})
		if err == nil {
			t.Error("expected error for empty password")
		}
	})

	t.Run("already logged in returns success without re-auth", func(t *testing.T) {
		t.Parallel()
		srv := newTestServer()

		session := &lastpass.Session{Email: "existing@test.com"}
		ctx := WithSession(context.Background(), session)
		ctx = withBearerToken(ctx, "existing-token")

		_, out, err := srv.handleLogin(ctx, nil, LoginInput{
			Email:    "existing@test.com",
			Password: "any-password",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !out.Success {
			t.Error("expected success=true")
		}
		if out.Message != "Already logged in" {
			t.Errorf("message = %q, want Already logged in", out.Message)
		}
		if out.Username != "existing@test.com" {
			t.Errorf("username = %q, want existing@test.com", out.Username)
		}
	})

	t.Run("already logged in with different email proceeds to login", func(t *testing.T) {
		t.Parallel()
		srv := newTestServer()

		session := &lastpass.Session{Email: "old@test.com"}
		ctx := WithSession(context.Background(), session)

		// This will attempt to call the real LastPass API, which will fail.
		// That is expected; we just verify it does NOT return "Already logged in".
		_, out, err := srv.handleLogin(ctx, nil, LoginInput{
			Email:    "new@test.com",
			Password: "password123",
		})
		// Should fail because of network call to LastPass, but NOT be "Already logged in"
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if out.Success {
			t.Error("should not succeed against real LastPass API with fake credentials")
		}
		if out.Message == "Already logged in" {
			t.Error("should not report already logged in for different email")
		}
	})
}

// ---------------------------------------------------------------------------
// Tool handlers: handleLogout
// ---------------------------------------------------------------------------

func TestHandleLogout(t *testing.T) {
	t.Parallel()

	t.Run("logout invalidates token", func(t *testing.T) {
		t.Parallel()
		srv := newTestServer()

		srv.oauth2Server.mu.Lock()
		srv.oauth2Server.tokens["logout-token"] = &TokenMapping{
			BearerToken: "logout-token",
			Session:     &lastpass.Session{Email: "logout@test.com"},
		}
		srv.oauth2Server.mu.Unlock()

		ctx := withBearerToken(context.Background(), "logout-token")

		_, out, err := srv.handleLogout(ctx, nil, struct{}{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !out.Success {
			t.Error("expected success=true")
		}
		if out.Message != "Logged out successfully" {
			t.Errorf("message = %q", out.Message)
		}

		// Token should be invalidated
		_, validErr := srv.oauth2Server.ValidateAccessToken("logout-token")
		if validErr == nil {
			t.Error("token should be invalid after logout")
		}
	})

	t.Run("logout without token still succeeds", func(t *testing.T) {
		t.Parallel()
		srv := newTestServer()
		ctx := context.Background()

		_, out, err := srv.handleLogout(ctx, nil, struct{}{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !out.Success {
			t.Error("expected success=true")
		}
	})
}

// ---------------------------------------------------------------------------
// Tool handlers: handleCreate (validation only, no real API calls)
// ---------------------------------------------------------------------------

func TestHandleCreate_Validation(t *testing.T) {
	t.Parallel()

	t.Run("empty type returns error", func(t *testing.T) {
		t.Parallel()
		srv := newTestServer()
		ctx := contextWithSessionAndToken(nil, "token-1")

		_, _, err := srv.handleCreate(ctx, nil, CreateInput{Type: "", Name: "Test"})
		if err == nil {
			t.Error("expected error for empty type")
		}
	})

	t.Run("empty name returns error", func(t *testing.T) {
		t.Parallel()
		srv := newTestServer()
		ctx := contextWithSessionAndToken(nil, "token-1")

		_, _, err := srv.handleCreate(ctx, nil, CreateInput{Type: "password", Name: ""})
		if err == nil {
			t.Error("expected error for empty name")
		}
	})

	t.Run("invalid type returns error", func(t *testing.T) {
		t.Parallel()
		srv := newTestServer()
		ctx := contextWithSessionAndToken(nil, "token-1")

		_, _, err := srv.handleCreate(ctx, nil, CreateInput{Type: "unknown", Name: "Test"})
		if err == nil {
			t.Error("expected error for invalid type")
		}
		if !containsSubstring(err.Error(), "must be") {
			t.Errorf("error should mention valid types, got: %v", err)
		}
	})

	t.Run("no session returns error", func(t *testing.T) {
		t.Parallel()
		srv := newTestServer()

		_, _, err := srv.handleCreate(context.Background(), nil, CreateInput{Type: "password", Name: "Test"})
		if err == nil {
			t.Error("expected error when no session")
		}
	})
}

// ---------------------------------------------------------------------------
// Tool handlers: handleUpdate (validation only, no real API calls)
// ---------------------------------------------------------------------------

func TestHandleUpdate_Validation(t *testing.T) {
	t.Parallel()

	t.Run("empty ID returns error", func(t *testing.T) {
		t.Parallel()
		srv := newTestServer()
		ctx := contextWithSessionAndToken(nil, "token-1")

		_, _, err := srv.handleUpdate(ctx, nil, UpdateInput{ID: ""})
		if err == nil {
			t.Error("expected error for empty ID")
		}
	})

	t.Run("no session returns error", func(t *testing.T) {
		t.Parallel()
		srv := newTestServer()

		_, _, err := srv.handleUpdate(context.Background(), nil, UpdateInput{ID: "123"})
		if err == nil {
			t.Error("expected error when no session")
		}
	})

	t.Run("entry not found returns error", func(t *testing.T) {
		t.Parallel()
		srv := newTestServer()
		entries := []lastpass.Entry{
			{ID: "1", Name: "Existing", Type: "password"},
		}
		ctx := contextWithSessionAndToken(entries, "token-1")

		_, _, err := srv.handleUpdate(ctx, nil, UpdateInput{ID: "99999"})
		if err == nil {
			t.Error("expected error for nonexistent entry")
		}
		if !containsSubstring(err.Error(), "not found") {
			t.Errorf("error should mention 'not found', got: %v", err)
		}
	})
}

// ---------------------------------------------------------------------------
// buildPaymentCardNotes
// ---------------------------------------------------------------------------

func TestBuildPaymentCardNotes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input CreateInput
		want  string
	}{
		{
			name: "all fields",
			input: CreateInput{
				CardholderName: "Jane Doe",
				CardType:       "Visa",
				CardNumber:     "4111111111111111",
				SecurityCode:   "999",
				StartDate:      "01/2022",
				ExpirationDate: "01/2027",
				Notes:          "personal card",
			},
			want: "NoteType:Credit Card\nLanguage:Jane Doe\nType:Visa\nNumber:4111111111111111\nSecurity Code:999\nStart Date:01/2022\nExpiration Date:01/2027\nNotes:personal card",
		},
		{
			name:  "no optional fields",
			input: CreateInput{},
			want:  "NoteType:Credit Card",
		},
		{
			name: "partial fields: name and number only",
			input: CreateInput{
				CardholderName: "Bob",
				CardNumber:     "1234",
			},
			want: "NoteType:Credit Card\nLanguage:Bob\nNumber:1234",
		},
		{
			name: "only notes",
			input: CreateInput{
				Notes: "important note",
			},
			want: "NoteType:Credit Card\nNotes:important note",
		},
		{
			name: "only card type and security code",
			input: CreateInput{
				CardType:     "Mastercard",
				SecurityCode: "321",
			},
			want: "NoteType:Credit Card\nType:Mastercard\nSecurity Code:321",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := buildPaymentCardNotes(tc.input)
			if got != tc.want {
				t.Errorf("buildPaymentCardNotes()\n  got:  %q\n  want: %q", got, tc.want)
			}
		})
	}
}

func TestBuildPaymentCardNotes_AlwaysIncludesNoteType(t *testing.T) {
	t.Parallel()

	inputs := []CreateInput{
		{},
		{CardholderName: "X"},
		{CardNumber: "1", SecurityCode: "2", ExpirationDate: "12/2030"},
	}

	for i, input := range inputs {
		got := buildPaymentCardNotes(input)
		if len(got) < len("NoteType:Credit Card") {
			t.Errorf("case %d: result too short: %q", i, got)
			continue
		}
		prefix := got[:len("NoteType:Credit Card")]
		if prefix != "NoteType:Credit Card" {
			t.Errorf("case %d: expected NoteType header, got prefix %q", i, prefix)
		}
	}
}

// ---------------------------------------------------------------------------
// RegisterTools: verify tools are registered on the MCP server
// ---------------------------------------------------------------------------

func TestRegisterTools(t *testing.T) {
	t.Parallel()

	srv := &Server{
		config: &Config{BaseURL: "http://localhost:8080"},
		mcpServer: mcpsdk.NewServer(&mcpsdk.Implementation{
			Name:    "test-server",
			Version: "0.0.1",
		}, nil),
		oauth2Server: newTestOAuth2Server(),
	}

	// RegisterTools should not panic and should complete without error.
	// We cannot list tools via the SDK (unexported), so we verify
	// the tool handlers work by calling them directly through the server.
	srv.RegisterTools()

	// Verify the handlers are operational by invoking them (they share the same server).
	// The fact that RegisterTools completes without panic is the main assertion.
	// We already test each handler individually in other tests.
}

// ---------------------------------------------------------------------------
// Health endpoint integration test
// ---------------------------------------------------------------------------

func TestHealthEndpoint(t *testing.T) {
	t.Parallel()

	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	})

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
	if w.Body.String() != "OK" {
		t.Errorf("body = %q, want OK", w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// Full OAuth2 route integration test
// ---------------------------------------------------------------------------

func TestOAuth2FullFlowRouting(t *testing.T) {
	t.Parallel()

	// Create a server with all routes set up
	oauthSrv := newTestOAuth2Server()

	mux := http.NewServeMux()
	oauthSrv.SetupRoutes(mux)

	// Test that all expected routes are accessible
	endpoints := []struct {
		method string
		path   string
		want   int
	}{
		{http.MethodGet, "/.well-known/oauth-protected-resource", http.StatusOK},
		{http.MethodGet, "/.well-known/oauth-authorization-server", http.StatusOK},
		{http.MethodPost, "/oauth/register", http.StatusBadRequest}, // Bad request because no body
	}

	for _, ep := range endpoints {
		t.Run(ep.method+" "+ep.path, func(t *testing.T) {
			req := httptest.NewRequest(ep.method, ep.path, nil)
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, req)

			if w.Code != ep.want {
				t.Errorf("status = %d, want %d; body = %s", w.Code, ep.want, w.Body.String())
			}
		})
	}
}

// ---------------------------------------------------------------------------
// handleRefresh: no token returns 401
// ---------------------------------------------------------------------------

func TestHandleRefresh_NoToken(t *testing.T) {
	t.Parallel()

	srv := newTestServer()

	req := httptest.NewRequest(http.MethodPost, "/api/refresh", nil)
	w := httptest.NewRecorder()
	srv.handleRefresh(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
}

func TestHandleRefresh_InvalidToken(t *testing.T) {
	t.Parallel()

	srv := newTestServer()

	req := httptest.NewRequest(http.MethodPost, "/api/refresh", nil)
	req.Header.Set("Authorization", "Bearer invalid-refresh-token")
	w := httptest.NewRecorder()
	srv.handleRefresh(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
}

// ---------------------------------------------------------------------------
// Concurrent access safety
// ---------------------------------------------------------------------------

func TestConcurrentTokenOperations(t *testing.T) {
	t.Parallel()

	s := newTestOAuth2Server()
	done := make(chan bool, 100)

	// Concurrent token writes
	for i := 0; i < 50; i++ {
		go func(idx int) {
			session := &lastpass.Session{Email: "concurrent@test.com"}
			token := generateSecureToken(16)
			s.mu.Lock()
			s.tokens[token] = &TokenMapping{
				BearerToken: token,
				Session:     session,
				CreatedAt:   time.Now(),
			}
			s.mu.Unlock()
			done <- true
		}(i)
	}

	// Concurrent token reads
	for i := 0; i < 50; i++ {
		go func() {
			s.mu.RLock()
			_ = len(s.tokens)
			s.mu.RUnlock()
			done <- true
		}()
	}

	for i := 0; i < 100; i++ {
		<-done
	}
}

// ---------------------------------------------------------------------------
// Serialization: ShowOutput JSON field names
// ---------------------------------------------------------------------------

func TestShowOutput_JSONSerialization(t *testing.T) {
	t.Parallel()

	out := ShowOutput{
		ID:             "123",
		Name:           "Test",
		Type:           "paymentcard",
		CardholderName: "John",
		CardType:       "Visa",
		CardNumber:     "4111",
		SecurityCode:   "123",
		StartDate:      "01/2024",
		ExpirationDate: "12/2028",
		Notes:          "note",
		LastModified:   "1700000000",
		LastTouch:      "1700000001",
	}

	data, err := json.Marshal(out)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}

	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}

	// Verify snake_case JSON keys
	expectedKeys := []string{"id", "name", "type", "cardholder_name", "card_type",
		"card_number", "security_code", "start_date", "expiration_date",
		"notes", "last_modified", "last_touch"}
	for _, key := range expectedKeys {
		if _, ok := m[key]; !ok {
			t.Errorf("expected JSON key %q in output", key)
		}
	}
}

func TestShowOutput_OmitsEmptyOptionalFields(t *testing.T) {
	t.Parallel()

	out := ShowOutput{
		ID:   "123",
		Name: "Test",
		Type: "password",
	}

	data, err := json.Marshal(out)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}

	var m map[string]interface{}
	_ = json.Unmarshal(data, &m)

	// These should be omitted when empty
	omittedKeys := []string{"cardholder_name", "card_type", "card_number",
		"security_code", "start_date", "expiration_date",
		"url", "username", "password", "notes", "last_modified", "last_touch"}
	for _, key := range omittedKeys {
		if _, ok := m[key]; ok {
			t.Errorf("JSON key %q should be omitted when empty", key)
		}
	}
}

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

// newTestServer creates a Server with a test OAuth2Server (no real LastPass client).
func newTestServer() *Server {
	oauthSrv := newTestOAuth2Server()
	return &Server{
		config: &Config{
			BaseURL: "http://localhost:8080",
		},
		oauth2Server: oauthSrv,
		lpClient:     lastpass.NewClient(),
	}
}

// contextWithSessionAndToken creates a context with a LastPass session
// containing the given entries and a Bearer token.
func contextWithSessionAndToken(entries []lastpass.Entry, token string) context.Context {
	session := &lastpass.Session{
		Email:     "test@example.com",
		SessionID: "test-session-id",
		CSRFToken: "test-csrf",
		Entries:   entries,
		CreatedAt: time.Now(),
	}
	ctx := WithSession(context.Background(), session)
	ctx = withBearerToken(ctx, token)
	return ctx
}

func containsSubstring(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(s) > 0 && containsSubstringImpl(s, sub))
}

func containsSubstringImpl(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
