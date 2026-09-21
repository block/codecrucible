package cli

import (
	"strings"
	"testing"
)

func TestTruncationMessageDistinguishesLowerCutoff(t *testing.T) {
	message := truncationMessage(8192, 65536)
	for _, want := range []string{"completion_tokens=8192", "max_output_tokens=65536", "provider/deployment caps"} {
		if !strings.Contains(message, want) {
			t.Errorf("missing %q: %s", want, message)
		}
	}
	if strings.Contains(message, "Increase --max-output-tokens") {
		t.Fatal("misleading retry advice")
	}
	if !strings.Contains(truncationMessage(8192, 8192), "Increase --max-output-tokens") {
		t.Fatal("missing advice for exhausted budget")
	}
}
