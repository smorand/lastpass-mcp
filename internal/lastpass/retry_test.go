package lastpass

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"
	"time"
)

func TestRetryWithBackoff(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		maxDuration time.Duration
		fn          func(calls *atomic.Int32) func() error
		wantCalls   int32
		wantErr     bool
	}{
		{
			name:        "succeeds on first try",
			maxDuration: 5 * time.Second,
			fn: func(calls *atomic.Int32) func() error {
				return func() error {
					calls.Add(1)
					return nil
				}
			},
			wantCalls: 1,
			wantErr:   false,
		},
		{
			name:        "fails then succeeds",
			maxDuration: 5 * time.Second,
			fn: func(calls *atomic.Int32) func() error {
				return func() error {
					n := calls.Add(1)
					if n < 3 {
						return fmt.Errorf("transient error #%d", n)
					}
					return nil
				}
			},
			wantCalls: 3,
			wantErr:   false,
		},
		{
			name:        "respects max duration",
			maxDuration: 800 * time.Millisecond,
			fn: func(calls *atomic.Int32) func() error {
				return func() error {
					calls.Add(1)
					return fmt.Errorf("permanent failure")
				}
			},
			// With 500ms initial delay, after first fail it waits 500ms,
			// then fails again; elapsed >= 800ms so it stops.
			// Expect at least 2 calls.
			wantCalls: 0, // checked separately
			wantErr:   true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var calls atomic.Int32
			ctx := context.Background()
			err := RetryWithBackoff(ctx, tc.maxDuration, tc.fn(&calls))

			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if calls.Load() < 2 {
					t.Errorf("expected at least 2 calls, got %d", calls.Load())
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tc.wantCalls > 0 && calls.Load() != tc.wantCalls {
				t.Errorf("expected %d calls, got %d", tc.wantCalls, calls.Load())
			}
		})
	}
}

func TestRetryWithBackoff_ContextCancellation(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	var calls atomic.Int32

	// Cancel after the first failure to ensure the retry loop exits.
	fn := func() error {
		n := calls.Add(1)
		if n == 1 {
			cancel()
		}
		return fmt.Errorf("error")
	}

	err := RetryWithBackoff(ctx, 30*time.Second, fn)
	if err == nil {
		t.Fatal("expected error after context cancellation, got nil")
	}

	// Should have been called once, then context cancelled during the wait.
	if calls.Load() < 1 {
		t.Errorf("expected at least 1 call, got %d", calls.Load())
	}
}

func TestRetryWithBackoff_ImmediateSuccess(t *testing.T) {
	t.Parallel()

	start := time.Now()
	err := RetryWithBackoff(context.Background(), 5*time.Second, func() error {
		return nil
	})
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Should return almost immediately (well under the initial 500ms delay).
	if elapsed > 100*time.Millisecond {
		t.Errorf("immediate success took %v, expected near-instant", elapsed)
	}
}
