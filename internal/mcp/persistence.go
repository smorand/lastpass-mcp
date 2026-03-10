package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"time"

	"cloud.google.com/go/storage"
	"lastpass-mcp/internal/lastpass"
)

const (
	stateObjectName = "oauth2-state.json"
	saveDebounce    = 5 * time.Second
)

// persistedSession is a wrapper around lastpass.Session that includes
// the DecryptionKey for persistence. The key is protected by GCS IAM.
type persistedSession struct {
	Email         string           `json:"email"`
	DecryptionKey []byte           `json:"decryption_key"`
	SessionID     string           `json:"session_id"`
	CSRFToken     string           `json:"csrf_token"`
	Entries       []lastpass.Entry `json:"entries"`
	CreatedAt     time.Time        `json:"created_at"`
}

// persistedToken represents a token mapping for persistence.
type persistedToken struct {
	BearerToken string           `json:"bearer_token"`
	Session     persistedSession `json:"session"`
	ClientID    string           `json:"client_id"`
	CreatedAt   time.Time        `json:"created_at"`
}

// persistedClient represents a registered client for persistence.
type persistedClient struct {
	ClientID     string   `json:"client_id"`
	ClientSecret string   `json:"client_secret"`
	RedirectURIs []string `json:"redirect_uris"`
}

// persistedState is the top-level structure saved to GCS.
type persistedState struct {
	Tokens  map[string]persistedToken  `json:"tokens"`
	Clients map[string]persistedClient `json:"clients"`
	SavedAt time.Time                  `json:"saved_at"`
}

// GCSPersistence handles saving and loading OAuth2 state to GCS.
type GCSPersistence struct {
	bucket  string
	client  *storage.Client
	saveCh  chan struct{}
}

// NewGCSPersistence creates a new GCS persistence handler.
func NewGCSPersistence(ctx context.Context, bucket string) (*GCSPersistence, error) {
	client, err := storage.NewClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("creating GCS client: %w", err)
	}

	p := &GCSPersistence{
		bucket: bucket,
		client: client,
		saveCh: make(chan struct{}, 1),
	}

	return p, nil
}

// Load reads the persisted state from GCS and populates the OAuth2Server maps.
func (p *GCSPersistence) Load(ctx context.Context, s *OAuth2Server) error {
	obj := p.client.Bucket(p.bucket).Object(stateObjectName)
	reader, err := obj.NewReader(ctx)
	if err != nil {
		if err == storage.ErrObjectNotExist {
			slog.Info("no persisted state found, starting fresh")
			return nil
		}
		return fmt.Errorf("reading state from GCS: %w", err)
	}
	defer func() { _ = reader.Close() }()

	data, err := io.ReadAll(reader)
	if err != nil {
		return fmt.Errorf("reading state data: %w", err)
	}

	var state persistedState
	if err := json.Unmarshal(data, &state); err != nil {
		return fmt.Errorf("parsing persisted state: %w", err)
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
		}
	}

	slog.Info("loaded persisted state", "tokens", len(state.Tokens), "clients", len(state.Clients), "saved_at", state.SavedAt)
	return nil
}

// Save writes the current OAuth2Server state to GCS.
func (p *GCSPersistence) Save(ctx context.Context, s *OAuth2Server) error {
	s.mu.RLock()
	state := persistedState{
		Tokens:  make(map[string]persistedToken),
		Clients: make(map[string]persistedClient),
		SavedAt: time.Now(),
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
		}
	}
	s.mu.RUnlock()

	data, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("marshaling state: %w", err)
	}

	obj := p.client.Bucket(p.bucket).Object(stateObjectName)
	writer := obj.NewWriter(ctx)
	writer.ContentType = "application/json"
	if _, err := writer.Write(data); err != nil {
		_ = writer.Close()
		return fmt.Errorf("writing state to GCS: %w", err)
	}
	if err := writer.Close(); err != nil {
		return fmt.Errorf("closing GCS writer: %w", err)
	}

	slog.Info("persisted state to GCS", "tokens", len(state.Tokens), "clients", len(state.Clients))
	return nil
}

// RequestSave signals that state should be saved. It debounces rapid saves.
func (p *GCSPersistence) RequestSave() {
	select {
	case p.saveCh <- struct{}{}:
	default:
		// Save already pending
	}
}

// RunSaveLoop runs a background loop that saves state when requested.
func (p *GCSPersistence) RunSaveLoop(ctx context.Context, s *OAuth2Server) {
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

// Close releases the GCS client resources.
func (p *GCSPersistence) Close() error {
	return p.client.Close()
}
