package lastpass

import (
	"context"
	"fmt"
	"log/slog"
	"time"
)

// RetryWithBackoff retries the given function with exponential backoff.
// It starts with a 500ms delay and doubles it after each attempt, stopping
// when the total elapsed time exceeds maxDuration or the context is cancelled.
func RetryWithBackoff(ctx context.Context, maxDuration time.Duration, fn func() error) error {
	delay := 500 * time.Millisecond
	start := time.Now()
	var attempt int

	for {
		attempt++
		err := fn()
		if err == nil {
			return nil
		}

		elapsed := time.Since(start)
		if elapsed >= maxDuration {
			return fmt.Errorf("retry exceeded max duration %v after %d attempts: %w", maxDuration, attempt, err)
		}

		remaining := maxDuration - elapsed
		if delay > remaining {
			delay = remaining
		}

		slog.Debug("retrying after error", "attempt", attempt, "delay", delay, "error", err)

		select {
		case <-ctx.Done():
			return fmt.Errorf("retry cancelled: %w", ctx.Err())
		case <-time.After(delay):
		}

		delay *= 2
	}
}
