// Package mcp provides the MCP (Model Context Protocol) server implementation
// for lastpass-mcp, enabling AI assistants to manage LastPass vault entries remotely.
package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"lastpass-mcp/internal/lastpass"
)

// contextKey is a custom type for context keys to avoid collisions.
type contextKey string

const (
	// sessionContextKey is the context key for the LastPass session.
	sessionContextKey contextKey = "lastpass_session"
	// bearerTokenContextKey is the context key for the Bearer token.
	bearerTokenContextKey contextKey = "bearer_token"
)

// WithSession adds a LastPass session to the context.
func WithSession(ctx context.Context, session *lastpass.Session) context.Context {
	return context.WithValue(ctx, sessionContextKey, session)
}

// GetSession retrieves the LastPass session from the context.
func GetSession(ctx context.Context) (*lastpass.Session, bool) {
	session, ok := ctx.Value(sessionContextKey).(*lastpass.Session)
	return session, ok
}

// withBearerToken adds a Bearer token to the context.
func withBearerToken(ctx context.Context, token string) context.Context {
	return context.WithValue(ctx, bearerTokenContextKey, token)
}

// getBearerToken retrieves the Bearer token from the context.
func getBearerToken(ctx context.Context) (string, bool) {
	token, ok := ctx.Value(bearerTokenContextKey).(string)
	return token, ok
}

// Config holds the MCP server configuration.
type Config struct {
	Host           string
	Port           int
	BaseURL        string
	SecretName     string
	SecretProject  string
	CredentialFile string
	Environment    string
}

// Server wraps the MCP server and HTTP server.
type Server struct {
	config       *Config
	mcpServer    *mcp.Server
	httpServer   *http.Server
	oauth2Server *OAuth2Server
	lpClient     *lastpass.Client
}

// NewServer creates a new MCP server with the given configuration.
func NewServer(cfg *Config) *Server {
	return &Server{
		config:   cfg,
		lpClient: lastpass.NewClient(),
	}
}

// extractBearerToken extracts the token from the Authorization header.
func extractBearerToken(r *http.Request) string {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return ""
	}

	const bearerPrefix = "Bearer "
	if !strings.HasPrefix(authHeader, bearerPrefix) {
		return ""
	}

	return strings.TrimPrefix(authHeader, bearerPrefix)
}

// authMiddleware wraps an HTTP handler with OAuth2 Bearer token authentication.
func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		accessToken := extractBearerToken(r)

		if accessToken == "" {
			w.Header().Set("WWW-Authenticate", fmt.Sprintf(
				`Bearer resource_metadata="%s/.well-known/oauth-protected-resource"`,
				s.config.BaseURL,
			))
			http.Error(w, "Unauthorized: Bearer token required", http.StatusUnauthorized)
			return
		}

		if s.oauth2Server == nil {
			http.Error(w, "OAuth not configured", http.StatusInternalServerError)
			return
		}

		session, err := s.oauth2Server.ValidateAccessToken(accessToken)
		if err != nil {
			slog.Warn("token validation failed", "error", err)
			w.Header().Set("WWW-Authenticate", fmt.Sprintf(
				`Bearer error="invalid_token", resource_metadata="%s/.well-known/oauth-protected-resource"`,
				s.config.BaseURL,
			))
			http.Error(w, "Unauthorized: invalid token", http.StatusUnauthorized)
			return
		}

		ctx := WithSession(r.Context(), session)
		ctx = withBearerToken(ctx, accessToken)
		r = r.WithContext(ctx)
		next.ServeHTTP(w, r)
	})
}

// MCP tool input/output types

// LoginInput is the input schema for lastpass_login tool.
type LoginInput struct {
	Email    string `json:"email" jsonschema:"LastPass account email address"`
	Password string `json:"password" jsonschema:"LastPass master password"`
}

// LoginOutput is the output schema for lastpass_login tool.
type LoginOutput struct {
	Success  bool   `json:"success"`
	Username string `json:"username,omitempty"`
	Message  string `json:"message"`
}

// LogoutOutput is the output schema for lastpass_logout tool.
type LogoutOutput struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

// SearchInput is the input schema for lastpass_search tool.
type SearchInput struct {
	Pattern string `json:"pattern" jsonschema:"Regular expression pattern to match against entry name, url, and username (case insensitive)"`
	Type    string `json:"type,omitempty" jsonschema:"Filter by entry type: password or paymentcard"`
}

// SearchResultItem represents a single search result.
type SearchResultItem struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	URL      string `json:"url"`
	Username string `json:"username"`
	Type     string `json:"type"`
}

// SearchOutput is the output schema for lastpass_search tool.
type SearchOutput struct {
	Results []SearchResultItem `json:"results"`
	Count   int                `json:"count"`
}

// ShowInput is the input schema for lastpass_show tool.
type ShowInput struct {
	ID string `json:"id" jsonschema:"LastPass entry ID"`
}

// CreateInput is the input schema for lastpass_create tool.
type CreateInput struct {
	Type           string `json:"type" jsonschema:"Entry type: password or paymentcard"`
	Name           string `json:"name" jsonschema:"Entry name"`
	URL            string `json:"url,omitempty" jsonschema:"Site URL (password type)"`
	Username       string `json:"username,omitempty" jsonschema:"Login username (password type)"`
	Password       string `json:"password,omitempty" jsonschema:"Login password (password type)"`
	Notes          string `json:"notes,omitempty" jsonschema:"Free text notes"`
	CardholderName string `json:"cardholder_name,omitempty" jsonschema:"Name on card (paymentcard type)"`
	CardType       string `json:"card_type,omitempty" jsonschema:"Card network e.g. Visa Mastercard (paymentcard type)"`
	CardNumber     string `json:"card_number,omitempty" jsonschema:"Card number (paymentcard type)"`
	SecurityCode   string `json:"security_code,omitempty" jsonschema:"CVV/CVC (paymentcard type)"`
	StartDate      string `json:"start_date,omitempty" jsonschema:"Card start date (paymentcard type)"`
	ExpirationDate string `json:"expiration_date,omitempty" jsonschema:"Card expiration date (paymentcard type)"`
}

// UpdateInput is the input schema for lastpass_update tool.
type UpdateInput struct {
	ID             string `json:"id" jsonschema:"LastPass entry ID to update"`
	Name           string `json:"name,omitempty" jsonschema:"New entry name"`
	URL            string `json:"url,omitempty" jsonschema:"New site URL"`
	Username       string `json:"username,omitempty" jsonschema:"New login username"`
	Password       string `json:"password,omitempty" jsonschema:"New login password"`
	Notes          string `json:"notes,omitempty" jsonschema:"New notes"`
	CardholderName string `json:"cardholder_name,omitempty" jsonschema:"New cardholder name"`
	CardType       string `json:"card_type,omitempty" jsonschema:"New card type"`
	CardNumber     string `json:"card_number,omitempty" jsonschema:"New card number"`
	SecurityCode   string `json:"security_code,omitempty" jsonschema:"New security code"`
	StartDate      string `json:"start_date,omitempty" jsonschema:"New start date"`
	ExpirationDate string `json:"expiration_date,omitempty" jsonschema:"New expiration date"`
}

// RegisterTools registers all LastPass vault management tools with the MCP server.
func (s *Server) RegisterTools() {
	// lastpass_login
	mcp.AddTool(s.mcpServer, &mcp.Tool{
		Name:        "lastpass_login",
		Description: "Authenticate to LastPass with email and master password. Creates or refreshes the LastPass session associated with the current Bearer token.",
	}, s.handleLogin)

	// lastpass_logout
	mcp.AddTool(s.mcpServer, &mcp.Tool{
		Name:        "lastpass_logout",
		Description: "Terminate the current LastPass session and invalidate the Bearer token.",
	}, s.handleLogout)

	// lastpass_search
	mcp.AddTool(s.mcpServer, &mcp.Tool{
		Name:        "lastpass_search",
		Description: "Search vault entries by regular expression pattern. Matches against name, url, and username (case insensitive). Optionally filter by entry type.",
	}, s.handleSearch)

	// lastpass_show
	mcp.AddTool(s.mcpServer, &mcp.Tool{
		Name:        "lastpass_show",
		Description: "Show full details of a vault entry by ID. Returns all fields including password or payment card details.",
	}, s.handleShow)

	// lastpass_create
	mcp.AddTool(s.mcpServer, &mcp.Tool{
		Name:        "lastpass_create",
		Description: "Create a new vault entry. Specify type as 'password' or 'paymentcard' and provide the relevant fields.",
	}, s.handleCreate)

	// lastpass_update
	mcp.AddTool(s.mcpServer, &mcp.Tool{
		Name:        "lastpass_update",
		Description: "Update an existing vault entry. Only provided fields are modified; others remain unchanged.",
	}, s.handleUpdate)
}

// handleLogin implements the lastpass_login MCP tool.
func (s *Server) handleLogin(ctx context.Context, req *mcp.CallToolRequest, input LoginInput) (
	*mcp.CallToolResult,
	LoginOutput,
	error,
) {
	if input.Email == "" {
		return nil, LoginOutput{}, fmt.Errorf("email is required")
	}
	if input.Password == "" {
		return nil, LoginOutput{}, fmt.Errorf("password is required")
	}

	// Check if already logged in with a valid session
	if session, ok := GetSession(ctx); ok && session != nil && session.Email == input.Email {
		return nil, LoginOutput{
			Success:  true,
			Username: session.Email,
			Message:  "Already logged in",
		}, nil
	}

	session, err := s.lpClient.Login(ctx, input.Email, input.Password)
	if err != nil {
		return nil, LoginOutput{
			Success: false,
			Message: fmt.Sprintf("Login failed: %v", err),
		}, nil
	}

	// Update the session associated with the current Bearer token
	if token, ok := getBearerToken(ctx); ok {
		s.oauth2Server.StoreTokenSession(token, session)
	}

	slog.Info("lastpass_login successful", "email", input.Email)

	return nil, LoginOutput{
		Success:  true,
		Username: session.Email,
		Message:  "Login successful",
	}, nil
}

// handleLogout implements the lastpass_logout MCP tool.
func (s *Server) handleLogout(ctx context.Context, req *mcp.CallToolRequest, input struct{}) (
	*mcp.CallToolResult,
	LogoutOutput,
	error,
) {
	if token, ok := getBearerToken(ctx); ok {
		s.oauth2Server.InvalidateToken(token)
	}

	slog.Info("lastpass_logout successful")

	return nil, LogoutOutput{
		Success: true,
		Message: "Logged out successfully",
	}, nil
}

// handleSearch implements the lastpass_search MCP tool.
func (s *Server) handleSearch(ctx context.Context, req *mcp.CallToolRequest, input SearchInput) (
	*mcp.CallToolResult,
	SearchOutput,
	error,
) {
	if input.Pattern == "" {
		return nil, SearchOutput{}, fmt.Errorf("pattern is required")
	}

	session, ok := GetSession(ctx)
	if !ok || session == nil {
		return nil, SearchOutput{}, fmt.Errorf("no active LastPass session")
	}

	re, err := regexp.Compile("(?i)" + input.Pattern)
	if err != nil {
		return nil, SearchOutput{}, fmt.Errorf("invalid regular expression: %v", err)
	}

	results := []SearchResultItem{}
	for _, entry := range session.Entries {
		// Use the entry's parsed type
		entryType := entry.Type
		if entryType == "" {
			entryType = "password"
		}

		// Filter by type if specified
		if input.Type != "" && input.Type != entryType {
			continue
		}

		// Match pattern against name, url, username
		if re.MatchString(entry.Name) || re.MatchString(entry.URL) || re.MatchString(entry.Username) {
			results = append(results, SearchResultItem{
				ID:       entry.ID,
				Name:     entry.Name,
				URL:      entry.URL,
				Username: entry.Username,
				Type:     entryType,
			})
		}
	}

	return nil, SearchOutput{
		Results: results,
		Count:   len(results),
	}, nil
}

// handleShow implements the lastpass_show MCP tool.
func (s *Server) handleShow(ctx context.Context, req *mcp.CallToolRequest, input ShowInput) (
	*mcp.CallToolResult,
	json.RawMessage,
	error,
) {
	if input.ID == "" {
		return nil, nil, fmt.Errorf("id is required")
	}

	session, ok := GetSession(ctx)
	if !ok || session == nil {
		return nil, nil, fmt.Errorf("no active LastPass session")
	}

	var found *lastpass.Entry
	for i := range session.Entries {
		if session.Entries[i].ID == input.ID {
			found = &session.Entries[i]
			break
		}
	}

	if found == nil {
		return nil, nil, fmt.Errorf("entry with ID %s not found", input.ID)
	}

	// Build response based on entry type
	var result map[string]interface{}
	if found.Type == "paymentcard" {
		result = map[string]interface{}{
			"id":              found.ID,
			"name":            found.Name,
			"type":            "paymentcard",
			"cardholder_name": found.CardholderName,
			"card_type":       found.CardType,
			"card_number":     found.CardNumber,
			"security_code":   found.SecurityCode,
			"start_date":      found.StartDate,
			"expiration_date": found.ExpirationDate,
			"notes":           found.Notes,
			"last_modified":   found.LastModified,
			"last_touch":      found.LastTouch,
		}
	} else {
		result = map[string]interface{}{
			"id":            found.ID,
			"name":          found.Name,
			"url":           found.URL,
			"username":      found.Username,
			"password":      found.Password,
			"notes":         found.Notes,
			"type":          "password",
			"last_modified": found.LastModified,
			"last_touch":    found.LastTouch,
		}
	}

	data, err := json.Marshal(result)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal entry: %w", err)
	}

	return nil, json.RawMessage(data), nil
}

// handleCreate implements the lastpass_create MCP tool.
func (s *Server) handleCreate(ctx context.Context, req *mcp.CallToolRequest, input CreateInput) (
	*mcp.CallToolResult,
	json.RawMessage,
	error,
) {
	if input.Type == "" {
		return nil, nil, fmt.Errorf("type is required (password or paymentcard)")
	}
	if input.Name == "" {
		return nil, nil, fmt.Errorf("name is required")
	}
	if input.Type != "password" && input.Type != "paymentcard" {
		return nil, nil, fmt.Errorf("type must be 'password' or 'paymentcard'")
	}

	session, ok := GetSession(ctx)
	if !ok || session == nil {
		return nil, nil, fmt.Errorf("no active LastPass session")
	}

	entry := lastpass.Entry{
		Name: input.Name,
		Type: input.Type,
	}

	if input.Type == "password" {
		entry.URL = input.URL
		entry.Username = input.Username
		entry.Password = input.Password
		entry.Notes = input.Notes
	} else {
		entry.URL = "http://sn"
		entry.Notes = buildPaymentCardNotes(input)
		entry.CardholderName = input.CardholderName
		entry.CardType = input.CardType
		entry.CardNumber = input.CardNumber
		entry.SecurityCode = input.SecurityCode
		entry.StartDate = input.StartDate
		entry.ExpirationDate = input.ExpirationDate
	}

	created, err := s.lpClient.CreateEntry(ctx, session, entry)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create entry: %w", err)
	}

	data, err := json.Marshal(created)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal created entry: %w", err)
	}

	slog.Info("lastpass_create successful", "name", input.Name, "type", input.Type)

	return nil, json.RawMessage(data), nil
}

// handleUpdate implements the lastpass_update MCP tool.
func (s *Server) handleUpdate(ctx context.Context, req *mcp.CallToolRequest, input UpdateInput) (
	*mcp.CallToolResult,
	json.RawMessage,
	error,
) {
	if input.ID == "" {
		return nil, nil, fmt.Errorf("id is required")
	}

	session, ok := GetSession(ctx)
	if !ok || session == nil {
		return nil, nil, fmt.Errorf("no active LastPass session")
	}

	// Find the current entry
	var current *lastpass.Entry
	for i := range session.Entries {
		if session.Entries[i].ID == input.ID {
			current = &session.Entries[i]
			break
		}
	}

	if current == nil {
		return nil, nil, fmt.Errorf("entry with ID %s not found", input.ID)
	}

	// Merge provided fields with existing values
	updated := *current
	if input.Name != "" {
		updated.Name = input.Name
	}
	if input.URL != "" {
		updated.URL = input.URL
	}
	if input.Username != "" {
		updated.Username = input.Username
	}
	if input.Password != "" {
		updated.Password = input.Password
	}
	if input.Notes != "" {
		updated.Notes = input.Notes
	}

	// Update payment card fields directly on the entry
	if current.Type == "paymentcard" {
		if input.CardholderName != "" {
			updated.CardholderName = input.CardholderName
		}
		if input.CardType != "" {
			updated.CardType = input.CardType
		}
		if input.CardNumber != "" {
			updated.CardNumber = input.CardNumber
		}
		if input.SecurityCode != "" {
			updated.SecurityCode = input.SecurityCode
		}
		if input.StartDate != "" {
			updated.StartDate = input.StartDate
		}
		if input.ExpirationDate != "" {
			updated.ExpirationDate = input.ExpirationDate
		}
	}

	result, err := s.lpClient.UpdateEntry(ctx, session, updated)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to update entry: %w", err)
	}

	data, err := json.Marshal(result)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal updated entry: %w", err)
	}

	slog.Info("lastpass_update successful", "id", input.ID)

	return nil, json.RawMessage(data), nil
}

// buildPaymentCardNotes builds structured notes for a payment card entry.
func buildPaymentCardNotes(input CreateInput) string {
	var lines []string
	lines = append(lines, "NoteType:Credit Card")
	if input.CardholderName != "" {
		lines = append(lines, "Language:"+input.CardholderName)
	}
	if input.CardType != "" {
		lines = append(lines, "Type:"+input.CardType)
	}
	if input.CardNumber != "" {
		lines = append(lines, "Number:"+input.CardNumber)
	}
	if input.SecurityCode != "" {
		lines = append(lines, "Security Code:"+input.SecurityCode)
	}
	if input.StartDate != "" {
		lines = append(lines, "Start Date:"+input.StartDate)
	}
	if input.ExpirationDate != "" {
		lines = append(lines, "Expiration Date:"+input.ExpirationDate)
	}
	if input.Notes != "" {
		lines = append(lines, "Notes:"+input.Notes)
	}
	return strings.Join(lines, "\n")
}

// Run starts the HTTP server and blocks until shutdown.
func (s *Server) Run(ctx context.Context) error {
	// Create the MCP server
	s.mcpServer = mcp.NewServer(&mcp.Implementation{
		Name:    "lastpass-mcp",
		Version: "1.0.0",
	}, nil)

	// Register tools
	s.RegisterTools()

	// Create the streamable HTTP handler for MCP
	mcpHandler := mcp.NewStreamableHTTPHandler(func(r *http.Request) *mcp.Server {
		return s.mcpServer
	}, &mcp.StreamableHTTPOptions{
		Stateless: false,
	})

	// Create HTTP mux for routing
	mux := http.NewServeMux()

	// Initialize OAuth2 server
	s.oauth2Server = NewOAuth2Server(&OAuth2ServerConfig{
		BaseURL:        s.config.BaseURL,
		SecretProject:  s.config.SecretProject,
		SecretName:     s.config.SecretName,
		CredentialFile: s.config.CredentialFile,
	})

	// Register OAuth2 routes (not protected by auth)
	s.oauth2Server.SetupRoutes(mux)
	slog.Info("OAuth2 endpoints enabled",
		"protected_resource", "/.well-known/oauth-protected-resource",
		"authorization_server", "/.well-known/oauth-authorization-server",
		"register", "/oauth/register",
		"authorize", "/oauth/authorize",
		"token", "/oauth/token",
	)

	// Health check endpoint (not protected by auth)
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	})

	// Wrap MCP handler with authentication middleware
	authedMCPHandler := s.authMiddleware(mcpHandler)

	// MCP endpoint (protected by OAuth2 Bearer token auth)
	mux.Handle("/", authedMCPHandler)

	slog.Info("authentication mode: OAuth2 Bearer tokens")

	// Create HTTP server
	addr := fmt.Sprintf("%s:%d", s.config.Host, s.config.Port)
	s.httpServer = &http.Server{
		Addr:    addr,
		Handler: mux,
	}

	// Setup graceful shutdown
	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, os.Interrupt, syscall.SIGTERM)

	// Start server in goroutine
	errChan := make(chan error, 1)
	go func() {
		slog.Info("starting MCP server", "addr", addr, "base_url", s.config.BaseURL)
		if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errChan <- err
		}
	}()

	// Wait for shutdown signal or error
	select {
	case err := <-errChan:
		return fmt.Errorf("server error: %w", err)
	case sig := <-shutdown:
		slog.Info("received shutdown signal", "signal", sig)
	case <-ctx.Done():
		slog.Info("context cancelled, shutting down")
	}

	// Graceful shutdown with timeout
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := s.httpServer.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("shutdown error: %w", err)
	}

	slog.Info("MCP server stopped")
	return nil
}
