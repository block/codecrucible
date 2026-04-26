package cli

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func TestRunListEndpoints_Success(t *testing.T) {
	var gotAuthHeader string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuthHeader = r.Header.Get("Authorization")
		if r.URL.Path != "/api/2.0/serving-endpoints" {
			http.Error(w, "unexpected path", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
                        "endpoints": [
                                {
                                        "name": "gpt-5.2",
                                        "state": {"ready": "READY"},
                                        "config": {"served_models": [{"model_name": "gpt-5.2"}]}
                                }
                        ]
                }`))
	}))
	defer server.Close()

	oldV := v
	t.Cleanup(func() { v = oldV })

	v = viper.New()
	v.Set("databricks-host", server.URL)
	v.Set("databricks-token", "test-token")

	cmd := &cobra.Command{}
	out := new(bytes.Buffer)
	cmd.SetOut(out)
	cmd.SetContext(context.Background())

	if err := runListEndpoints(cmd, nil); err != nil {
		t.Fatalf("runListEndpoints() error = %v", err)
	}
	if gotAuthHeader != "Bearer test-token" {
		t.Fatalf("Authorization header = %q, want %q", gotAuthHeader, "Bearer test-token")
	}

	output := out.String()
	for _, want := range []string{"ENDPOINT", "gpt-5.2", "auto-detected"} {
		if !strings.Contains(output, want) {
			t.Fatalf("output missing %q:\n%s", want, output)
		}
	}
}

func TestRunListEndpoints_MissingHost(t *testing.T) {
	oldV := v
	t.Cleanup(func() { v = oldV })

	v = viper.New()
	v.Set("databricks-token", "token")

	err := runListEndpoints(&cobra.Command{}, nil)
	if err == nil || !strings.Contains(err.Error(), "DATABRICKS_HOST is not set") {
		t.Fatalf("expected missing host error, got %v", err)
	}
}

func TestRunListEndpoints_MissingToken(t *testing.T) {
	oldV := v
	t.Cleanup(func() { v = oldV })

	v = viper.New()
	v.Set("databricks-host", "https://example.com")

	err := runListEndpoints(&cobra.Command{}, nil)
	if err == nil || !strings.Contains(err.Error(), "DATABRICKS_TOKEN is not set") {
		t.Fatalf("expected missing token error, got %v", err)
	}
}

func TestDescribeModel_PrefersExternalModel(t *testing.T) {
	endpoint := databricksEndpoint{
		Config: databricksEndpointCfg{
			ServedEntities: []databricksServedEntity{
				{
					ExternalModel: &databricksExternalModel{Provider: "openai", Name: "gpt-5.2"},
				},
			},
		},
	}

	got := describeModel(endpoint)
	if got != "openai/gpt-5.2" {
		t.Fatalf("describeModel() = %q, want %q", got, "openai/gpt-5.2")
	}
}

func TestUsageHint(t *testing.T) {
	if got := usageHint("gpt-5.2"); got != "auto-detected" {
		t.Fatalf("usageHint() for known model = %q, want %q", got, "auto-detected")
	}
	if got := usageHint("custom-endpoint"); got != "DATABRICKS_ENDPOINT=custom-endpoint" {
		t.Fatalf("usageHint() for unknown model = %q", got)
	}
}

func TestTruncateStr(t *testing.T) {
	if got := truncateStr("short", 10); got != "short" {
		t.Fatalf("truncateStr short = %q, want %q", got, "short")
	}
	if got := truncateStr("abcdefghijklmnopqrstuvwxyz", 5); got != "abcde..." {
		t.Fatalf("truncateStr long = %q, want %q", got, "abcde...")
	}
}
