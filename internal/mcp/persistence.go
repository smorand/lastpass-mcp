package mcp

import "context"

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
