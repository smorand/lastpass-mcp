package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"time"

	kms "cloud.google.com/go/kms/apiv1"
	kmspb "cloud.google.com/go/kms/apiv1/kmspb"
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
	bucket     string
	client     *storage.Client
	kmsClient  *kms.KeyManagementClient
	kmsKeyName string
	saveCh     chan struct{}
}

// NewGCSPersistence creates a new GCS persistence handler.
// If kmsKeyName is provided, DecryptionKey fields will be encrypted/decrypted with Cloud KMS.
func NewGCSPersistence(ctx context.Context, bucket string, kmsKeyName string) (*GCSPersistence, error) {
	client, err := storage.NewClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("creating GCS client: %w", err)
	}

	p := &GCSPersistence{
		bucket:     bucket,
		client:     client,
		kmsKeyName: kmsKeyName,
		saveCh:     make(chan struct{}, 1),
	}

	if kmsKeyName != "" {
		kmsClient, err := kms.NewKeyManagementClient(ctx)
		if err != nil {
			_ = client.Close()
			return nil, fmt.Errorf("creating KMS client: %w", err)
		}
		p.kmsClient = kmsClient
		slog.Info("KMS encryption enabled for state persistence", "key", kmsKeyName)
	}

	return p, nil
}

// encryptKey encrypts a DecryptionKey with Cloud KMS. Returns plaintext if KMS is not configured.
func (p *GCSPersistence) encryptKey(ctx context.Context, plaintext []byte) ([]byte, error) {
	if p.kmsClient == nil || len(plaintext) == 0 {
		return plaintext, nil
	}
	resp, err := p.kmsClient.Encrypt(ctx, &kmspb.EncryptRequest{
		Name:      p.kmsKeyName,
		Plaintext: plaintext,
	})
	if err != nil {
		return nil, fmt.Errorf("KMS encrypt: %w", err)
	}
	return resp.Ciphertext, nil
}

// decryptKey decrypts a DecryptionKey with Cloud KMS. Returns ciphertext as is if KMS is not configured.
// If decryption fails (e.g. data was stored in plaintext before KMS was enabled), the original data
// is returned as is to support migration from plaintext to encrypted storage.
func (p *GCSPersistence) decryptKey(ctx context.Context, ciphertext []byte) ([]byte, error) {
	if p.kmsClient == nil || len(ciphertext) == 0 {
		return ciphertext, nil
	}
	resp, err := p.kmsClient.Decrypt(ctx, &kmspb.DecryptRequest{
		Name:       p.kmsKeyName,
		Ciphertext: ciphertext,
	})
	if err != nil {
		slog.Warn("KMS decrypt failed, assuming plaintext (pre-KMS data)", "error", err)
		return ciphertext, nil
	}
	return resp.Plaintext, nil
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
		decryptionKey, err := p.decryptKey(ctx, pt.Session.DecryptionKey)
		if err != nil {
			return fmt.Errorf("decrypting key for token %s: %w", key, err)
		}
		s.tokens[key] = &TokenMapping{
			BearerToken: pt.BearerToken,
			Session: &lastpass.Session{
				Email:         pt.Session.Email,
				DecryptionKey: decryptionKey,
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
		encryptedKey, err := p.encryptKey(ctx, tm.Session.DecryptionKey)
		if err != nil {
			s.mu.RUnlock()
			return fmt.Errorf("encrypting key for token %s: %w", key, err)
		}
		state.Tokens[key] = persistedToken{
			BearerToken: tm.BearerToken,
			Session: persistedSession{
				Email:         tm.Session.Email,
				DecryptionKey: encryptedKey,
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

// Close releases the GCS and KMS client resources.
func (p *GCSPersistence) Close() error {
	if p.kmsClient != nil {
		_ = p.kmsClient.Close()
	}
	return p.client.Close()
}
