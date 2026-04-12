// Package observability provides logging for lastpass-mcp.
package observability

import (
	"log/slog"
	"os"
	"strings"
)

// InitLogger sets up the global slog logger with JSON output.
func InitLogger(level string) {
	var slogLevel slog.Level
	switch strings.ToLower(level) {
	case "debug":
		slogLevel = slog.LevelDebug
	case "warn", "warning":
		slogLevel = slog.LevelWarn
	case "error":
		slogLevel = slog.LevelError
	default:
		slogLevel = slog.LevelInfo
	}

	handler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slogLevel,
		ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
			switch a.Key {
			case "token", "api_key", "secret", "password", "content", "prompt", "response":
				return slog.String(a.Key, "[REDACTED]")
			}
			return a
		},
	})

	slog.SetDefault(slog.New(handler))
}
