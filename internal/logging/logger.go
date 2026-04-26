package logging

import (
	"io"
	"log/slog"
	"os"
)

// NewLogger creates a structured slog.Logger.
// When verbose is true, the level is set to DEBUG and output is JSON.
// When verbose is false, the level is set to INFO and output is text.
func NewLogger(verbose bool) *slog.Logger {
	return NewLoggerWithWriter(verbose, os.Stderr)
}

// NewLoggerWithWriter creates a structured slog.Logger writing to the given writer.
func NewLoggerWithWriter(verbose bool, w io.Writer) *slog.Logger {
	if verbose {
		return slog.New(slog.NewJSONHandler(w, &slog.HandlerOptions{
			Level: slog.LevelDebug,
		}))
	}
	return slog.New(slog.NewTextHandler(w, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
}
