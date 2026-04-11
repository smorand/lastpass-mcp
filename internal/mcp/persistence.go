package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"lastpass-mcp/internal/lastpass"
)

const (
	saveDebounce = 5 * time.Second
	stateFile    = "oauth2-state.json"
)

// Persistence defines the interface for OAuth2 state persistence.
type Persistence interface {
	Load(ctx context.Context, s *OAuth2Server) error
	Save(ctx context.Context, s *OAuth2Server) error
	RequestSave()
	RunSaveLoop(ctx context.Context, s *OAuth2Server)
	Close() error
}

// NoOpPersistence is an in-memory only persistence that does nothing.
// Sessions are lost on server restart.
type NoOpPersistence struct{}

func (p *NoOpPersistence) Load(_ context.Context, _ *OAuth2Server) error { return nil }
func (p *NoOpPersistence) Save(_ context.Context, _ *OAuth2Server) error { return nil }
func (p *NoOpPersistence) RequestSave()                                  {}
func (p *NoOpPersistence) RunSaveLoop(_ context.Context, _ *OAuth2Server) {
	// Block until context is cancelled to match the expected goroutine lifecycle
	<-make(chan struct{})
}
func (p *NoOpPersistence) Close() error { return nil }

// persistedSession wraps session fields for JSON serialization.
// DecryptionKey is explicitly included here because lastpass.Session
// intentionally omits it from JSON to prevent accidental leaks.
type persistedSession struct {
	Email         string           `json:"email"`
	DecryptionKey []byte           `json:"decryption_key"`
	SessionID     string           `json:"session_id"`
	CSRFToken     string           `json:"csrf_token"`
	Entries       []lastpass.Entry `json:"entries"`
	CreatedAt     time.Time        `json:"created_at"`
}

// persistedToken represents a token mapping for file persistence.
type persistedToken struct {
	BearerToken string           `json:"bearer_token"`
	Session     persistedSession `json:"session"`
	ClientID    string           `json:"client_id"`
	CreatedAt   time.Time        `json:"created_at"`
}

// persistedClient represents a registered client for file persistence.
type persistedClient struct {
	ClientID     string    `json:"client_id"`
	ClientSecret string    `json:"client_secret"`
	RedirectURIs []string  `json:"redirect_uris"`
	CreatedAt    time.Time `json:"created_at"`
}

// persistedState is the top-level structure saved to the JSON file.
type persistedState struct {
	Tokens  map[string]persistedToken  `json:"tokens"`
	Clients map[string]persistedClient `json:"clients"`
}

// FilePersistence handles saving and loading OAuth2 state to a JSON file on disk.
type FilePersistence struct {
	path   string
	saveCh chan struct{}
}

// NewFilePersistence creates a new file-based persistence handler.
// dataDir is the directory where the state file will be stored.
func NewFilePersistence(dataDir string) (*FilePersistence, error) {
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		return nil, fmt.Errorf("creating data directory %s: %w", dataDir, err)
	}

	return &FilePersistence{
		path:   filepath.Join(dataDir, stateFile),
		saveCh: make(chan struct{}, 1),
	}, nil
}

// Load reads the persisted state from the JSON file and populates the OAuth2Server maps.
func (p *FilePersistence) Load(_ context.Context, s *OAuth2Server) error {
	data, err := os.ReadFile(p.path)
	if os.IsNotExist(err) {
		slog.Info("no persisted state file found, starting fresh", "path", p.path)
		return nil
	}
	if err != nil {
		return fmt.Errorf("reading state file %s: %w", p.path, err)
	}

	var state persistedState
	if err := json.Unmarshal(data, &state); err != nil {
		return fmt.Errorf("parsing state file %s: %w", p.path, err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	for key, pt := range state.Tokens {
		s.tokens[key] = &TokenMapping{
			BearerToken: pt.BearerToken,
			Session: &lastpass.Session{
				Email:         pt.Session.Email,
				DecryptionKey: pt.Session.DecryptionKey,
				SessionID:     pt.Session.SessionID,
				CSRFToken:     pt.Session.CSRFToken,
				Entries:       pt.Session.Entries,
				CreatedAt:     pt.Session.CreatedAt,
			},
			ClientID:  pt.ClientID,
			CreatedAt: pt.CreatedAt,
		}
	}

	for key, pc := range state.Clients {
		s.clients[key] = &RegisteredClient{
			ClientID:     pc.ClientID,
			ClientSecret: pc.ClientSecret,
			RedirectURIs: pc.RedirectURIs,
			CreatedAt:    pc.CreatedAt,
		}
	}

	slog.Info("loaded persisted state from file", "path", p.path, "tokens", len(state.Tokens), "clients", len(state.Clients))
	return nil
}

// Save writes the current OAuth2Server state to the JSON file.
func (p *FilePersistence) Save(_ context.Context, s *OAuth2Server) error {
	s.mu.RLock()
	state := persistedState{
		Tokens:  make(map[string]persistedToken, len(s.tokens)),
		Clients: make(map[string]persistedClient, len(s.clients)),
	}

	for key, tm := range s.tokens {
		if tm.Session == nil {
			continue
		}
		state.Tokens[key] = persistedToken{
			BearerToken: tm.BearerToken,
			Session: persistedSession{
				Email:         tm.Session.Email,
				DecryptionKey: tm.Session.DecryptionKey,
				SessionID:     tm.Session.SessionID,
				CSRFToken:     tm.Session.CSRFToken,
				Entries:       tm.Session.Entries,
				CreatedAt:     tm.Session.CreatedAt,
			},
			ClientID:  tm.ClientID,
			CreatedAt: tm.CreatedAt,
		}
	}

	for key, rc := range s.clients {
		state.Clients[key] = persistedClient{
			ClientID:     rc.ClientID,
			ClientSecret: rc.ClientSecret,
			RedirectURIs: rc.RedirectURIs,
			CreatedAt:    rc.CreatedAt,
		}
	}
	s.mu.RUnlock()

	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling state: %w", err)
	}

	// Write atomically: write to temp file then rename
	tmpPath := p.path + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0600); err != nil {
		return fmt.Errorf("writing temp state file: %w", err)
	}
	if err := os.Rename(tmpPath, p.path); err != nil {
		return fmt.Errorf("renaming state file: %w", err)
	}

	slog.Info("persisted state to file", "path", p.path, "tokens", len(state.Tokens), "clients", len(state.Clients))
	return nil
}

// RequestSave signals that state should be saved. It debounces rapid saves.
func (p *FilePersistence) RequestSave() {
	select {
	case p.saveCh <- struct{}{}:
	default:
		// Save already pending
	}
}

// RunSaveLoop runs a background loop that saves state when requested.
func (p *FilePersistence) RunSaveLoop(ctx context.Context, s *OAuth2Server) {
	for {
		select {
		case <-ctx.Done():
			// Final save on shutdown
			saveCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			if err := p.Save(saveCtx, s); err != nil {
				slog.Error("failed to save state on shutdown", "error", err)
			}
			cancel()
			return
		case <-p.saveCh:
			// Debounce: wait a bit for more changes
			time.Sleep(saveDebounce)
			if err := p.Save(ctx, s); err != nil {
				slog.Error("failed to save state", "error", err)
			}
		}
	}
}

// Close is a no-op for file persistence (no resources to release).
func (p *FilePersistence) Close() error { return nil }
