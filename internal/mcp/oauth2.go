// Package mcp provides the MCP (Model Context Protocol) server implementation
// for lastpass-mcp, enabling AI assistants to manage LastPass vault entries remotely.
// This file implements the OAuth2 Authorization Server endpoints (RFC 8414, 7591, 9728).
//
// OAuth2 Flow for LastPass MCP:
// 1. Client discovers auth server via /.well-known/oauth-protected-resource
// 2. Client fetches auth server metadata from /.well-known/oauth-authorization-server
// 3. Client registers via /oauth/register (Dynamic Client Registration)
// 4. Client redirects user to /oauth/authorize, server shows LastPass login page
// 5. User submits LastPass credentials, server authenticates with LastPass API
// 6. Server generates auth code and redirects to client's redirect_uri
// 7. Client exchanges code at /oauth/token, receives Bearer token mapped to LastPass session
// 8. Client sends Bearer token on MCP requests, server validates and injects session
package mcp

import (
	"crypto/rand"
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
	"sync"
	"time"

	"lastpass-mcp/internal/lastpass"
)

// allowedRedirectHosts defines the hardcoded allowlist of redirect URI host:port
// combinations. Hardcoded for security: no config that could be misconfigured.
var allowedRedirectHosts = []struct {
	scheme string
	host   string // host:port
}{
	{"http", "localhost:8000"},
	{"http", "localhost:3000"},
	{"http", "127.0.0.1:8000"},
	{"http", "127.0.0.1:3000"},
}

// allowedExactRedirectURIs defines exact match redirect URIs for production callbacks.
var allowedExactRedirectURIs = []string{
	"https://lastpass.mcp.scm-platform.org/oauth/callback",
}

// isRedirectURIAllowed checks whether a redirect URI is in the hardcoded allowlist.
// Localhost URIs on ports 8000 and 3000 are allowed with any path.
// The production callback URL must match exactly.
func isRedirectURIAllowed(rawURI string) bool {
	if rawURI == "" {
		return false
	}

	// Check exact matches first (production callbacks)
	for _, allowed := range allowedExactRedirectURIs {
		if rawURI == allowed {
			return true
		}
	}

	parsed, err := url.Parse(rawURI)
	if err != nil {
		return false
	}

	// Reject URIs with fragments (OAuth2 spec requirement)
	if parsed.Fragment != "" {
		return false
	}

	// Determine host:port for comparison
	hostPort := parsed.Host
	if parsed.Port() == "" {
		// No explicit port: add default for scheme
		if parsed.Scheme == "http" {
			hostPort = parsed.Hostname() + ":80"
		} else if parsed.Scheme == "https" {
			hostPort = parsed.Hostname() + ":443"
		}
	}

	for _, allowed := range allowedRedirectHosts {
		if parsed.Scheme == allowed.scheme && hostPort == allowed.host {
			return true
		}
	}

	return false
}

//go:embed templates/login.html
var loginTemplatesFS embed.FS

// loginPageTemplate holds the parsed login page template.
var loginPageTemplate *template.Template

func init() {
	var err error
	loginPageTemplate, err = template.ParseFS(loginTemplatesFS, "templates/login.html")
	if err != nil {
		panic(fmt.Sprintf("failed to parse login template: %v", err))
	}
}

// loginPageData holds the data for rendering the login page template.
type loginPageData struct {
	ClientID            string
	RedirectURI         string
	State               string
	CodeChallenge       string
	CodeChallengeMethod string
	Error               string
}

// ProtectedResourceMetadata represents RFC 9728 protected resource metadata.
type ProtectedResourceMetadata struct {
	Resource               string   `json:"resource"`
	AuthorizationServers   []string `json:"authorization_servers"`
	BearerMethodsSupported []string `json:"bearer_methods_supported,omitempty"`
	ScopesSupported        []string `json:"scopes_supported,omitempty"`
}

// AuthorizationServerMetadata represents RFC 8414 authorization server metadata.
type AuthorizationServerMetadata struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	RegistrationEndpoint              string   `json:"registration_endpoint,omitempty"`
	ScopesSupported                   []string `json:"scopes_supported,omitempty"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	GrantTypesSupported               []string `json:"grant_types_supported"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
}

// ClientRegistrationRequest represents RFC 7591 dynamic client registration request.
type ClientRegistrationRequest struct {
	ClientName              string   `json:"client_name,omitempty"`
	RedirectURIs            []string `json:"redirect_uris"`
	GrantTypes              []string `json:"grant_types,omitempty"`
	ResponseTypes           []string `json:"response_types,omitempty"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method,omitempty"`
}

// ClientRegistrationResponse represents RFC 7591 dynamic client registration response.
type ClientRegistrationResponse struct {
	ClientID                string   `json:"client_id"`
	ClientSecret            string   `json:"client_secret,omitempty"`
	ClientIDIssuedAt        int64    `json:"client_id_issued_at,omitempty"`
	ClientSecretExpiresAt   int64    `json:"client_secret_expires_at,omitempty"`
	RedirectURIs            []string `json:"redirect_uris"`
	GrantTypes              []string `json:"grant_types,omitempty"`
	ResponseTypes           []string `json:"response_types,omitempty"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method,omitempty"`
}

// TokenResponse represents an OAuth2 token response.
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

// TokenErrorResponse represents an OAuth2 error response.
type TokenErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
}

// RegisteredClient stores registered OAuth client information.
type RegisteredClient struct {
	ClientID     string
	ClientSecret string
	RedirectURIs []string
	CreatedAt    time.Time
}

// AuthState stores OAuth authorization state.
type AuthState struct {
	ClientID      string
	RedirectURI   string
	State         string // client's state
	CodeChallenge string
	CodeMethod    string
	CreatedAt     time.Time
}

// AuthCode stores issued authorization codes.
type AuthCode struct {
	Code          string
	ClientID      string
	RedirectURI   string
	CodeChallenge string
	CodeMethod    string
	Session       *lastpass.Session
	CreatedAt     time.Time
}

// TokenMapping maps a Bearer token to a LastPass session.
type TokenMapping struct {
	BearerToken string
	Session     *lastpass.Session
	ClientID    string
	CreatedAt   time.Time
}

// OAuth2Server handles OAuth2 authorization server endpoints.
type OAuth2Server struct {
	baseURL        string
	secretProject  string
	secretName     string
	credentialFile string

	// In-memory stores
	clients map[string]*RegisteredClient
	states  map[string]*AuthState
	codes   map[string]*AuthCode
	tokens  map[string]*TokenMapping
	mu      sync.RWMutex

	// Persistence
	persistence *GCSPersistence
}

// OAuth2ServerConfig holds configuration for the OAuth2 server.
type OAuth2ServerConfig struct {
	BaseURL        string
	SecretProject  string
	SecretName     string
	CredentialFile string
	StateBucket    string
}

// NewOAuth2Server creates a new OAuth2 authorization server.
func NewOAuth2Server(cfg *OAuth2ServerConfig) *OAuth2Server {
	s := &OAuth2Server{
		baseURL:        cfg.BaseURL,
		secretProject:  cfg.SecretProject,
		secretName:     cfg.SecretName,
		credentialFile: cfg.CredentialFile,
		clients:        make(map[string]*RegisteredClient),
		states:         make(map[string]*AuthState),
		codes:          make(map[string]*AuthCode),
		tokens:         make(map[string]*TokenMapping),
	}

	// Start background cleanup goroutine
	go s.cleanupExpired()

	return s
}

// cleanupExpired removes expired states, codes, and tokens periodically.
func (s *OAuth2Server) cleanupExpired() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		s.mu.Lock()
		now := time.Now()
		for key, state := range s.states {
			if now.Sub(state.CreatedAt) > 10*time.Minute {
				delete(s.states, key)
			}
		}
		for key, code := range s.codes {
			if now.Sub(code.CreatedAt) > 10*time.Minute {
				delete(s.codes, key)
			}
		}
		s.mu.Unlock()
	}
}

// SetPersistence sets the GCS persistence handler and starts the save loop.
func (s *OAuth2Server) SetPersistence(p *GCSPersistence) {
	s.persistence = p
}

// requestSave signals the persistence layer to save state.
func (s *OAuth2Server) requestSave() {
	if s.persistence != nil {
		s.persistence.RequestSave()
	}
}

// SetupRoutes registers all OAuth2 endpoints on the given mux.
func (s *OAuth2Server) SetupRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/.well-known/oauth-protected-resource", s.HandleProtectedResourceMetadata)
	mux.HandleFunc("/.well-known/oauth-authorization-server", s.HandleAuthorizationServerMetadata)
	mux.HandleFunc("/oauth/register", s.HandleClientRegistration)
	mux.HandleFunc("/oauth/authorize", s.HandleAuthorize)
	mux.HandleFunc("/oauth/token", s.HandleToken)
}

// HandleProtectedResourceMetadata serves RFC 9728 protected resource metadata.
// GET /.well-known/oauth-protected-resource
func (s *OAuth2Server) HandleProtectedResourceMetadata(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	metadata := ProtectedResourceMetadata{
		Resource:               s.baseURL,
		AuthorizationServers:   []string{s.baseURL},
		BearerMethodsSupported: []string{"header"},
		ScopesSupported:        []string{"vault:read", "vault:write"},
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(metadata)
}

// HandleAuthorizationServerMetadata serves RFC 8414 authorization server metadata.
// GET /.well-known/oauth-authorization-server
func (s *OAuth2Server) HandleAuthorizationServerMetadata(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	metadata := AuthorizationServerMetadata{
		Issuer:                            s.baseURL,
		AuthorizationEndpoint:             s.baseURL + "/oauth/authorize",
		TokenEndpoint:                     s.baseURL + "/oauth/token",
		RegistrationEndpoint:              s.baseURL + "/oauth/register",
		ScopesSupported:                   []string{"vault:read", "vault:write"},
		ResponseTypesSupported:            []string{"code"},
		GrantTypesSupported:               []string{"authorization_code", "refresh_token"},
		CodeChallengeMethodsSupported:     []string{"S256"},
		TokenEndpointAuthMethodsSupported: []string{"client_secret_basic", "client_secret_post"},
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(metadata)
}

// HandleClientRegistration implements RFC 7591 Dynamic Client Registration.
// POST /oauth/register
func (s *OAuth2Server) HandleClientRegistration(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req ClientRegistrationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeOAuthError(w, "invalid_request", "Invalid JSON body", http.StatusBadRequest)
		return
	}

	if len(req.RedirectURIs) == 0 {
		writeOAuthError(w, "invalid_request", "redirect_uris is required", http.StatusBadRequest)
		return
	}

	// Validate all redirect URIs against the allowlist
	for _, uri := range req.RedirectURIs {
		if !isRedirectURIAllowed(uri) {
			writeOAuthError(w, "invalid_request", fmt.Sprintf("redirect_uri not allowed: %s", uri), http.StatusBadRequest)
			return
		}
	}

	// Generate client credentials
	clientID := generateSecureToken(16)
	clientSecret := generateSecureToken(32)

	client := &RegisteredClient{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURIs: req.RedirectURIs,
		CreatedAt:    time.Now(),
	}

	s.mu.Lock()
	s.clients[clientID] = client
	s.mu.Unlock()
	s.requestSave()

	slog.Info("registered new OAuth client", "client_id", clientID, "client_name", req.ClientName)

	resp := ClientRegistrationResponse{
		ClientID:                clientID,
		ClientSecret:            clientSecret,
		ClientIDIssuedAt:        time.Now().Unix(),
		ClientSecretExpiresAt:   0,
		RedirectURIs:            req.RedirectURIs,
		GrantTypes:              []string{"authorization_code", "refresh_token"},
		ResponseTypes:           []string{"code"},
		TokenEndpointAuthMethod: "client_secret_basic",
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(resp)
}

// HandleAuthorize handles both GET (show login page) and POST (process login) for authorization.
// GET /oauth/authorize?client_id=xxx&redirect_uri=xxx&response_type=code&state=xxx&code_challenge=xxx&code_challenge_method=S256
// POST /oauth/authorize (form submission with email + password)
func (s *OAuth2Server) HandleAuthorize(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.handleAuthorizeGet(w, r)
	case http.MethodPost:
		s.handleAuthorizePost(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleAuthorizeGet renders the LastPass login page.
func (s *OAuth2Server) handleAuthorizeGet(w http.ResponseWriter, r *http.Request) {
	clientID := r.URL.Query().Get("client_id")
	redirectURI := r.URL.Query().Get("redirect_uri")
	responseType := r.URL.Query().Get("response_type")
	state := r.URL.Query().Get("state")
	codeChallenge := r.URL.Query().Get("code_challenge")
	codeChallengeMethod := r.URL.Query().Get("code_challenge_method")

	// Validate required parameters
	if clientID == "" {
		writeOAuthError(w, "invalid_request", "client_id is required", http.StatusBadRequest)
		return
	}
	if redirectURI == "" {
		writeOAuthError(w, "invalid_request", "redirect_uri is required", http.StatusBadRequest)
		return
	}
	if responseType != "code" {
		writeOAuthError(w, "unsupported_response_type", "Only 'code' response type is supported", http.StatusBadRequest)
		return
	}

	// Validate client is registered (no auto-registration)
	s.mu.RLock()
	client, exists := s.clients[clientID]
	s.mu.RUnlock()

	if !exists {
		writeOAuthError(w, "invalid_client", "Client not registered. Use /oauth/register first.", http.StatusUnauthorized)
		return
	}

	// Validate redirect_uri is in client's registered list (no auto-addition)
	validRedirect := false
	for _, uri := range client.RedirectURIs {
		if uri == redirectURI {
			validRedirect = true
			break
		}
	}
	if !validRedirect {
		writeOAuthError(w, "invalid_request", "redirect_uri not registered for this client", http.StatusBadRequest)
		return
	}

	// PKCE is mandatory: require code_challenge with S256
	if codeChallenge == "" {
		writeOAuthError(w, "invalid_request", "code_challenge is required (PKCE mandatory)", http.StatusBadRequest)
		return
	}
	if codeChallengeMethod != "S256" {
		writeOAuthError(w, "invalid_request", "code_challenge_method must be S256", http.StatusBadRequest)
		return
	}

	// Generate internal state key and store auth state
	internalState := generateSecureToken(32)
	authState := &AuthState{
		ClientID:      clientID,
		RedirectURI:   redirectURI,
		State:         state,
		CodeChallenge: codeChallenge,
		CodeMethod:    codeChallengeMethod,
		CreatedAt:     time.Now(),
	}

	s.mu.Lock()
	s.states[internalState] = authState
	s.mu.Unlock()

	// Render login page with hidden OAuth2 params
	data := loginPageData{
		ClientID:            clientID,
		RedirectURI:         redirectURI,
		State:               internalState,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: codeChallengeMethod,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := loginPageTemplate.Execute(w, data); err != nil {
		slog.Error("failed to render login template", "error", err)
		http.Error(w, "Failed to render login page", http.StatusInternalServerError)
	}
}

// handleAuthorizePost processes the login form submission.
func (s *OAuth2Server) handleAuthorizePost(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, "invalid_request", "Invalid form data", http.StatusBadRequest)
		return
	}

	clientID := r.FormValue("client_id")
	redirectURI := r.FormValue("redirect_uri")
	internalState := r.FormValue("state")
	codeChallenge := r.FormValue("code_challenge")
	codeChallengeMethod := r.FormValue("code_challenge_method")
	email := r.FormValue("email")
	password := r.FormValue("password")

	// Look up the auth state
	s.mu.RLock()
	authState, exists := s.states[internalState]
	s.mu.RUnlock()

	if !exists {
		writeOAuthError(w, "invalid_request", "Invalid or expired authorization state", http.StatusBadRequest)
		return
	}

	// Validate email and password are provided
	if email == "" || password == "" {
		s.renderLoginError(w, "Email and master password are required.", clientID, redirectURI, internalState, codeChallenge, codeChallengeMethod)
		return
	}

	// Authenticate with LastPass
	lpClient := lastpass.NewClient()
	session, err := lpClient.Login(r.Context(), email, password)
	if err != nil {
		slog.Error("LastPass login failed", "email", email, "error", err)
		s.renderLoginError(w, "Invalid master password or email. Please try again.", clientID, redirectURI, internalState, codeChallenge, codeChallengeMethod)
		return
	}

	slog.Info("LastPass login successful", "email", email)

	// Remove the used auth state
	s.mu.Lock()
	delete(s.states, internalState)
	s.mu.Unlock()

	// Generate authorization code
	code := generateSecureToken(32)
	codeEntry := &AuthCode{
		Code:          code,
		ClientID:      authState.ClientID,
		RedirectURI:   authState.RedirectURI,
		CodeChallenge: authState.CodeChallenge,
		CodeMethod:    authState.CodeMethod,
		Session:       session,
		CreatedAt:     time.Now(),
	}

	s.mu.Lock()
	s.codes[code] = codeEntry
	s.mu.Unlock()

	// Redirect back to client with code and client's original state
	redirectURL := authState.RedirectURI + "?code=" + code
	if authState.State != "" {
		redirectURL += "&state=" + authState.State
	}

	slog.Info("redirecting to client with authorization code", "redirect_uri", authState.RedirectURI)
	http.Redirect(w, r, redirectURL, http.StatusFound)
}

// renderLoginError re-renders the login page with an error message.
func (s *OAuth2Server) renderLoginError(w http.ResponseWriter, errMsg, clientID, redirectURI, state, codeChallenge, codeChallengeMethod string) {
	data := loginPageData{
		ClientID:            clientID,
		RedirectURI:         redirectURI,
		State:               state,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: codeChallengeMethod,
		Error:               errMsg,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	if err := loginPageTemplate.Execute(w, data); err != nil {
		slog.Error("failed to render login template", "error", err)
		http.Error(w, "Failed to render login page", http.StatusInternalServerError)
	}
}

// HandleToken handles token exchange and refresh requests.
// POST /oauth/token
func (s *OAuth2Server) HandleToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, "invalid_request", "Invalid form data", http.StatusBadRequest)
		return
	}

	grantType := r.FormValue("grant_type")
	code := r.FormValue("code")
	clientID := r.FormValue("client_id")
	codeVerifier := r.FormValue("code_verifier")
	refreshToken := r.FormValue("refresh_token")

	// Also check for client credentials in Authorization header (Basic auth)
	if clientID == "" {
		if username, _, ok := r.BasicAuth(); ok {
			clientID = username
		}
	}

	switch grantType {
	case "authorization_code":
		s.handleAuthorizationCodeGrant(w, clientID, code, codeVerifier)
	case "refresh_token":
		s.handleRefreshTokenGrant(w, clientID, refreshToken)
	default:
		writeOAuthError(w, "unsupported_grant_type", "Only authorization_code and refresh_token are supported", http.StatusBadRequest)
	}
}

// handleAuthorizationCodeGrant handles the authorization_code grant type.
func (s *OAuth2Server) handleAuthorizationCodeGrant(w http.ResponseWriter, clientID, code, codeVerifier string) {
	if code == "" {
		writeOAuthError(w, "invalid_request", "code is required", http.StatusBadRequest)
		return
	}

	// Look up and consume the authorization code (single use)
	s.mu.Lock()
	codeEntry, exists := s.codes[code]
	if exists {
		delete(s.codes, code)
	}
	s.mu.Unlock()

	if !exists {
		writeOAuthError(w, "invalid_grant", "Invalid or expired authorization code", http.StatusBadRequest)
		return
	}

	// Validate client_id matches
	if clientID != "" && clientID != codeEntry.ClientID {
		writeOAuthError(w, "invalid_client", "client_id mismatch", http.StatusUnauthorized)
		return
	}

	// Validate PKCE (mandatory)
	if codeVerifier == "" {
		writeOAuthError(w, "invalid_request", "code_verifier is required (PKCE mandatory)", http.StatusBadRequest)
		return
	}
	if !validatePKCE(codeVerifier, codeEntry.CodeChallenge, codeEntry.CodeMethod) {
		writeOAuthError(w, "invalid_grant", "Invalid code_verifier", http.StatusBadRequest)
		return
	}

	// Generate Bearer token and map it to the LastPass session
	bearerToken := generateSecureToken(32)
	refreshToken := generateSecureToken(32)

	tokenMapping := &TokenMapping{
		BearerToken: bearerToken,
		Session:     codeEntry.Session,
		ClientID:    codeEntry.ClientID,
		CreatedAt:   time.Now(),
	}

	s.mu.Lock()
	s.tokens[bearerToken] = tokenMapping
	// Also store refresh token pointing to the same mapping
	s.tokens[refreshToken] = tokenMapping
	s.mu.Unlock()
	s.requestSave()

	resp := TokenResponse{
		AccessToken:  bearerToken,
		TokenType:    "Bearer",
		ExpiresIn:    86400, // 24 hours
		RefreshToken: refreshToken,
		Scope:        "vault:read vault:write",
	}

	slog.Info("token issued for client", "client_id", codeEntry.ClientID)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// handleRefreshTokenGrant handles the refresh_token grant type.
func (s *OAuth2Server) handleRefreshTokenGrant(w http.ResponseWriter, clientID, refreshToken string) {
	if refreshToken == "" {
		writeOAuthError(w, "invalid_request", "refresh_token is required", http.StatusBadRequest)
		return
	}

	// Look up the refresh token
	s.mu.RLock()
	tokenMapping, exists := s.tokens[refreshToken]
	s.mu.RUnlock()

	if !exists || tokenMapping.Session == nil {
		writeOAuthError(w, "invalid_grant", "Invalid or expired refresh token", http.StatusBadRequest)
		return
	}

	// Generate new Bearer token
	newBearerToken := generateSecureToken(32)
	newRefreshToken := generateSecureToken(32)

	newMapping := &TokenMapping{
		BearerToken: newBearerToken,
		Session:     tokenMapping.Session,
		ClientID:    tokenMapping.ClientID,
		CreatedAt:   time.Now(),
	}

	s.mu.Lock()
	// Remove old refresh token
	delete(s.tokens, refreshToken)
	// Store new tokens
	s.tokens[newBearerToken] = newMapping
	s.tokens[newRefreshToken] = newMapping
	s.mu.Unlock()
	s.requestSave()

	resp := TokenResponse{
		AccessToken:  newBearerToken,
		TokenType:    "Bearer",
		ExpiresIn:    86400,
		RefreshToken: newRefreshToken,
		Scope:        "vault:read vault:write",
	}

	slog.Info("token refreshed for client", "client_id", tokenMapping.ClientID)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// ValidateAccessToken validates a Bearer token and returns the associated LastPass session.
func (s *OAuth2Server) ValidateAccessToken(token string) (*lastpass.Session, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	mapping, exists := s.tokens[token]
	if !exists {
		return nil, fmt.Errorf("invalid or expired access token")
	}

	if mapping.Session == nil {
		return nil, fmt.Errorf("session has been invalidated")
	}

	return mapping.Session, nil
}

// InvalidateToken removes a Bearer token mapping.
func (s *OAuth2Server) InvalidateToken(token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.tokens, token)
}

// StoreTokenSession stores or updates the session for a given Bearer token.
func (s *OAuth2Server) StoreTokenSession(token string, session *lastpass.Session) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if mapping, exists := s.tokens[token]; exists {
		mapping.Session = session
	}
}

// Helper functions

// generateSecureToken generates a cryptographically secure random token.
func generateSecureToken(length int) string {
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		slog.Warn("crypto/rand failed, using fallback", "error", err)
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return base64.URLEncoding.EncodeToString(b)[:length+length/3]
}

// validatePKCE validates the PKCE code_verifier against the stored code_challenge.
func validatePKCE(verifier, challenge, method string) bool {
	if method != "S256" && method != "" {
		return false
	}

	// For S256: challenge = BASE64URL(SHA256(verifier))
	h := sha256.Sum256([]byte(verifier))
	computed := base64.RawURLEncoding.EncodeToString(h[:])

	return computed == challenge
}

// writeOAuthError writes a standard OAuth2 error response.
func writeOAuthError(w http.ResponseWriter, errorCode, description string, statusCode int) {
	resp := TokenErrorResponse{
		Error:            errorCode,
		ErrorDescription: description,
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(resp)
}
