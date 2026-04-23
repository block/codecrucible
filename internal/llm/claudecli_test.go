package llm

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNewClaudeCLIClient_UnsupportedHeaders(t *testing.T) {
	_, err := NewClaudeCLIClient(ClientConfig{
		Headers: http.Header{
			"X-Feature-Flag": []string{"enabled"},
		},
	})
	if err == nil {
		t.Fatal("expected unsupported header error")
	}
	if !strings.Contains(err.Error(), "unsupported header") {
		t.Fatalf("error = %v, want unsupported header", err)
	}
}

func TestClaudeCLIClient_ChatCompletionStructuredOutput(t *testing.T) {
	dir := t.TempDir()
	argsFile := filepath.Join(dir, "args.txt")
	stdinFile := filepath.Join(dir, "stdin.txt")
	claudePath := filepath.Join(dir, "claude")

	script := `#!/bin/sh
printf '%s\n' "$@" >"$TEST_ARGS_FILE"
cat >"$TEST_STDIN_FILE"
cat <<'JSON'
{"type":"result","subtype":"success","is_error":false,"result":"","structured_output":{"ok":true},"stop_reason":"max_tokens","usage":{"input_tokens":123,"output_tokens":45},"modelUsage":{"claude-sonnet-4-6":{"inputTokens":123,"outputTokens":45}}}
JSON
`
	if err := os.WriteFile(claudePath, []byte(script), 0755); err != nil {
		t.Fatalf("write fake claude: %v", err)
	}

	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("TEST_ARGS_FILE", argsFile)
	t.Setenv("TEST_STDIN_FILE", stdinFile)

	client, err := NewClaudeCLIClient(ClientConfig{
		Headers: http.Header{
			"Anthropic-Beta": []string{"context-1m-2025-08-07", "other-beta"},
		},
		Timeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewClaudeCLIClient returned error: %v", err)
	}

	schema := json.RawMessage(`{"type":"object","properties":{"ok":{"type":"boolean"}},"required":["ok"]}`)
	resp, err := client.ChatCompletion(context.Background(), ChatRequest{
		Model:          "claude-sonnet-4-6",
		Messages:       []Message{{Role: "system", Content: "system prompt"}, {Role: "user", Content: "user prompt"}},
		ResponseSchema: &schema,
	})
	if err != nil {
		t.Fatalf("ChatCompletion returned error: %v", err)
	}

	if resp.Content != `{"ok":true}` {
		t.Fatalf("Content = %q, want structured output JSON", resp.Content)
	}
	if resp.FinishReason != "length" {
		t.Fatalf("FinishReason = %q, want %q", resp.FinishReason, "length")
	}
	if resp.Model != "claude-sonnet-4-6" {
		t.Fatalf("Model = %q, want %q", resp.Model, "claude-sonnet-4-6")
	}
	if resp.Usage.PromptTokens != 123 || resp.Usage.CompletionTokens != 45 {
		t.Fatalf("Usage = %+v, want prompt=123 completion=45", resp.Usage)
	}

	argsData, err := os.ReadFile(argsFile)
	if err != nil {
		t.Fatalf("read args file: %v", err)
	}
	args := string(argsData)
	for _, want := range []string{
		"-p",
		"--output-format",
		"json",
		"--tools",
		"--permission-mode",
		"bypassPermissions",
		"--model",
		"claude-sonnet-4-6",
		"--system-prompt",
		"system prompt",
		"--json-schema",
		string(schema),
		"--betas",
		"context-1m-2025-08-07",
		"other-beta",
	} {
		if !strings.Contains(args, want+"\n") {
			t.Fatalf("expected args to contain %q, got:\n%s", want, args)
		}
	}

	stdinData, err := os.ReadFile(stdinFile)
	if err != nil {
		t.Fatalf("read stdin file: %v", err)
	}
	if got := string(stdinData); got != "user prompt" {
		t.Fatalf("stdin = %q, want %q", got, "user prompt")
	}
}

func TestClaudeCLIClient_ContextLengthError(t *testing.T) {
	dir := t.TempDir()
	claudePath := filepath.Join(dir, "claude")
	script := "#!/bin/sh\necho 'prompt is too long for this model' >&2\nexit 1\n"
	if err := os.WriteFile(claudePath, []byte(script), 0755); err != nil {
		t.Fatalf("write fake claude: %v", err)
	}

	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

	client, err := NewClaudeCLIClient(ClientConfig{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("NewClaudeCLIClient returned error: %v", err)
	}

	_, err = client.ChatCompletion(context.Background(), ChatRequest{
		Model:    "claude-sonnet-4-6",
		Messages: []Message{{Role: "user", Content: "hi"}},
	})
	if err != ErrContextLengthExceeded {
		t.Fatalf("error = %v, want %v", err, ErrContextLengthExceeded)
	}
}
