package logging

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
)

func TestNewLoggerWithWriter_VerboseOutputsJSON(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLoggerWithWriter(true, &buf)

	logger.Info("test message", "key", "value")

	output := buf.String()
	if output == "" {
		t.Fatal("expected log output, got empty string")
	}

	// Verbose mode should produce valid JSON.
	var parsed map[string]any
	if err := json.Unmarshal([]byte(output), &parsed); err != nil {
		t.Fatalf("verbose output is not valid JSON: %v\noutput: %s", err, output)
	}

	if parsed["msg"] != "test message" {
		t.Errorf("expected msg 'test message', got %v", parsed["msg"])
	}
}

func TestNewLoggerWithWriter_VerboseIncludesDebug(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLoggerWithWriter(true, &buf)

	logger.Debug("debug message")

	output := buf.String()
	if !strings.Contains(output, "debug message") {
		t.Errorf("expected debug message in verbose output, got: %s", output)
	}
}

func TestNewLoggerWithWriter_NonVerboseExcludesDebug(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLoggerWithWriter(false, &buf)

	logger.Debug("debug message")

	output := buf.String()
	if strings.Contains(output, "debug message") {
		t.Errorf("expected no debug message in non-verbose output, got: %s", output)
	}
}

func TestNewLoggerWithWriter_NonVerboseIncludesInfo(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLoggerWithWriter(false, &buf)

	logger.Info("info message")

	output := buf.String()
	if !strings.Contains(output, "info message") {
		t.Errorf("expected info message in non-verbose output, got: %s", output)
	}
}

func TestNewLoggerWithWriter_NonVerboseIsText(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLoggerWithWriter(false, &buf)

	logger.Info("test message")

	output := buf.String()
	// Text handler output should not be valid JSON.
	var parsed map[string]any
	if err := json.Unmarshal([]byte(output), &parsed); err == nil {
		t.Errorf("non-verbose output should not be JSON, got: %s", output)
	}
}

func TestNewLogger_ReturnsSlogLogger(t *testing.T) {
	logger := NewLogger(false)
	if logger == nil {
		t.Fatal("expected non-nil logger")
	}

	// Verify it's a valid *slog.Logger by checking it implements the interface.
	var _ *slog.Logger = logger
}
