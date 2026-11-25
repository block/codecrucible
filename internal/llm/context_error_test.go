package llm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestContextLengthDiagnosis(t *testing.T) {
	for _, nested := range []bool{false, true} {
		t.Run(fmt.Sprintf("nested=%v", nested), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Diagnosis beyond the log truncation boundary must survive.
				diagnosis := map[string]string{"code": "context_length_exceeded", "message": strings.Repeat("padding ", 40) + "Current length is 517967 while limit is 256000"}
				w.WriteHeader(http.StatusBadRequest)
				if nested {
					json.NewEncoder(w).Encode(map[string]any{"error": diagnosis})
				} else {
					json.NewEncoder(w).Encode(diagnosis)
				}
			}))
			defer server.Close()
			client := NewClient(ClientConfig{BaseURL: server.URL})
			_, err := client.ChatCompletion(context.Background(), ChatRequest{
				MaxTokens: 1000, UseMaxCompletionTokens: true,
				ModelParams: map[string]any{"max_completion_tokens": 40960},
			})
			var diagnosis *ContextLengthError
			if !errors.Is(err, ErrContextLengthExceeded) || !errors.As(err, &diagnosis) {
				t.Fatalf("lost diagnosis: %v", err)
			}
			if diagnosis.CurrentTokens != 517967 || diagnosis.LimitTokens != 256000 || diagnosis.OutputTokens != 40960 {
				t.Fatalf("wrong diagnosis or wire reservation: %+v", diagnosis)
			}
			if strings.Contains(err.Error(), "padding") {
				t.Fatal("raw provider message retained")
			}
		})
	}
}

func TestContextLengthDiagnosisFallback(t *testing.T) {
	for _, message := range []string{
		"context_length_exceeded", "Current length is -10 while limit is 5",
		"Current length is 0 while limit is 0", "Current length is 5 while limit is 10",
		"Current length is 999999999999999999999999999 while limit is 100",
		"prompt is too long: 300000 tokens > 256000 maximum",
	} {
		if err := contextLengthError(message, []byte(`{"max_tokens":40960}`)); err != ErrContextLengthExceeded {
			t.Errorf("unsupported diagnosis %q: %v", message, err)
		}
	}
}
