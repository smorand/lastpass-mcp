package mcp

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"cloud.google.com/go/firestore"
	kms "cloud.google.com/go/kms/apiv1"
	kmspb "cloud.google.com/go/kms/apiv1/kmspb"
	"google.golang.org/api/iterator"
	"lastpass-mcp/internal/lastpass"
)

const (
	saveDebounce      = 5 * time.Second
	tokensCollection  = "tokens"
	clientsCollection = "clients"
)

// Persistence defines the interface for OAuth2 state persistence.
type Persistence interface {
	Load(ctx context.Context, s *OAuth2Server) error
	Save(ctx context.Context, s *OAuth2Server) error
	RequestSave()
	RunSaveLoop(ctx context.Context, s *OAuth2Server)
	Close() error
}

// persistedSession is a wrapper around lastpass.Session that includes
// the DecryptionKey for persistence. The key is protected by KMS encryption.
type persistedSession struct {
	Email         string           `json:"email" firestore:"email"`
	DecryptionKey []byte           `json:"decryption_key" firestore:"decryption_key"`
	SessionID     string           `json:"session_id" firestore:"session_id"`
	CSRFToken     string           `json:"csrf_token" firestore:"csrf_token"`
	Entries       []lastpass.Entry `json:"entries" firestore:"entries"`
	CreatedAt     time.Time        `json:"created_at" firestore:"created_at"`
}

// persistedToken represents a token mapping for persistence.
type persistedToken struct {
	BearerToken string           `json:"bearer_token" firestore:"bearer_token"`
	Session     persistedSession `json:"session" firestore:"session"`
	ClientID    string           `json:"client_id" firestore:"client_id"`
	CreatedAt   time.Time        `json:"created_at" firestore:"created_at"`
}

// persistedClient represents a registered client for persistence.
type persistedClient struct {
	ClientID     string   `json:"client_id" firestore:"client_id"`
	ClientSecret string   `json:"client_secret" firestore:"client_secret"`
	RedirectURIs []string `json:"redirect_uris" firestore:"redirect_uris"`
}

// FirestorePersistence handles saving and loading OAuth2 state to Firestore.
type FirestorePersistence struct {
	projectID  string
	database   string
	client     *firestore.Client
	kmsClient  *kms.KeyManagementClient
	kmsKeyName string
	saveCh     chan struct{}
}

// NewFirestorePersistence creates a new Firestore persistence handler.
// If kmsKeyName is provided, DecryptionKey fields will be encrypted/decrypted with Cloud KMS.
func NewFirestorePersistence(ctx context.Context, projectID, database, kmsKeyName string) (*FirestorePersistence, error) {
	client, err := firestore.NewClientWithDatabase(ctx, projectID, database)
	if err != nil {
		return nil, fmt.Errorf("creating Firestore client: %w", err)
	}

	p := &FirestorePersistence{
		projectID:  projectID,
		database:   database,
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
func (p *FirestorePersistence) encryptKey(ctx context.Context, plaintext []byte) ([]byte, error) {
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
func (p *FirestorePersistence) decryptKey(ctx context.Context, ciphertext []byte) ([]byte, error) {
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

// Load reads the persisted state from Firestore and populates the OAuth2Server maps.
func (p *FirestorePersistence) Load(ctx context.Context, s *OAuth2Server) error {
	tokenCount := 0
	clientCount := 0

	// Load tokens
	tokenIter := p.client.Collection(tokensCollection).Documents(ctx)
	defer tokenIter.Stop()
	for {
		doc, err := tokenIter.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return fmt.Errorf("reading tokens from Firestore: %w", err)
		}

		var pt persistedToken
		if err := doc.DataTo(&pt); err != nil {
			slog.Warn("skipping malformed token document", "id", doc.Ref.ID, "error", err)
			continue
		}

		decryptionKey, err := p.decryptKey(ctx, pt.Session.DecryptionKey)
		if err != nil {
			return fmt.Errorf("decrypting key for token %s: %w", doc.Ref.ID, err)
		}

		s.mu.Lock()
		s.tokens[doc.Ref.ID] = &TokenMapping{
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
		s.mu.Unlock()
		tokenCount++
	}

	// Load clients
	clientIter := p.client.Collection(clientsCollection).Documents(ctx)
	defer clientIter.Stop()
	for {
		doc, err := clientIter.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return fmt.Errorf("reading clients from Firestore: %w", err)
		}

		var pc persistedClient
		if err := doc.DataTo(&pc); err != nil {
			slog.Warn("skipping malformed client document", "id", doc.Ref.ID, "error", err)
			continue
		}

		s.mu.Lock()
		s.clients[doc.Ref.ID] = &RegisteredClient{
			ClientID:     pc.ClientID,
			ClientSecret: pc.ClientSecret,
			RedirectURIs: pc.RedirectURIs,
		}
		s.mu.Unlock()
		clientCount++
	}

	slog.Info("loaded persisted state from Firestore", "tokens", tokenCount, "clients", clientCount)
	return nil
}

// Save writes the current OAuth2Server state to Firestore.
func (p *FirestorePersistence) Save(ctx context.Context, s *OAuth2Server) error {
	// Snapshot state under read lock
	s.mu.RLock()
	tokenSnapshots := make(map[string]persistedToken, len(s.tokens))
	for key, tm := range s.tokens {
		if tm.Session == nil {
			continue
		}
		tokenSnapshots[key] = persistedToken{
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

	clientSnapshots := make(map[string]persistedClient, len(s.clients))
	for key, rc := range s.clients {
		clientSnapshots[key] = persistedClient{
			ClientID:     rc.ClientID,
			ClientSecret: rc.ClientSecret,
			RedirectURIs: rc.RedirectURIs,
		}
	}
	s.mu.RUnlock()

	// Write tokens (encrypt keys outside the lock)
	currentTokenIDs := make(map[string]bool, len(tokenSnapshots))
	for key, pt := range tokenSnapshots {
		currentTokenIDs[key] = true
		encryptedKey, err := p.encryptKey(ctx, pt.Session.DecryptionKey)
		if err != nil {
			return fmt.Errorf("encrypting key for token %s: %w", key, err)
		}
		pt.Session.DecryptionKey = encryptedKey
		if _, err := p.client.Collection(tokensCollection).Doc(key).Set(ctx, pt); err != nil {
			return fmt.Errorf("writing token %s to Firestore: %w", key, err)
		}
	}

	// Write clients
	currentClientIDs := make(map[string]bool, len(clientSnapshots))
	for key, pc := range clientSnapshots {
		currentClientIDs[key] = true
		if _, err := p.client.Collection(clientsCollection).Doc(key).Set(ctx, pc); err != nil {
			return fmt.Errorf("writing client %s to Firestore: %w", key, err)
		}
	}

	// Delete stale token docs
	tokenIter := p.client.Collection(tokensCollection).Documents(ctx)
	defer tokenIter.Stop()
	for {
		doc, err := tokenIter.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			slog.Warn("error listing token docs for cleanup", "error", err)
			break
		}
		if !currentTokenIDs[doc.Ref.ID] {
			if _, err := doc.Ref.Delete(ctx); err != nil {
				slog.Warn("failed to delete stale token doc", "id", doc.Ref.ID, "error", err)
			}
		}
	}

	// Delete stale client docs
	clientIter := p.client.Collection(clientsCollection).Documents(ctx)
	defer clientIter.Stop()
	for {
		doc, err := clientIter.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			slog.Warn("error listing client docs for cleanup", "error", err)
			break
		}
		if !currentClientIDs[doc.Ref.ID] {
			if _, err := doc.Ref.Delete(ctx); err != nil {
				slog.Warn("failed to delete stale client doc", "id", doc.Ref.ID, "error", err)
			}
		}
	}

	slog.Info("persisted state to Firestore", "tokens", len(tokenSnapshots), "clients", len(clientSnapshots))
	return nil
}

// RequestSave signals that state should be saved. It debounces rapid saves.
func (p *FirestorePersistence) RequestSave() {
	select {
	case p.saveCh <- struct{}{}:
	default:
		// Save already pending
	}
}

// RunSaveLoop runs a background loop that saves state when requested.
func (p *FirestorePersistence) RunSaveLoop(ctx context.Context, s *OAuth2Server) {
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

// Close releases the Firestore and KMS client resources.
func (p *FirestorePersistence) Close() error {
	if p.kmsClient != nil {
		_ = p.kmsClient.Close()
	}
	return p.client.Close()
}
