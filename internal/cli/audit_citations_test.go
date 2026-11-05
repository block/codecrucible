package cli

import (
	"strings"
	"testing"

	"github.com/block/codecrucible/internal/auditctx"
	"github.com/block/codecrucible/internal/chunk"
	"github.com/block/codecrucible/internal/sourceindex"
)

func TestCitedContextRetainsAdmittedEvidenceOnly(t *testing.T) {
	source := sourceindex.New(map[string]string{"routes/a.go": "one\ntwo\nthree", "other.go": "private"})
	text, _ := citedAuditContext(auditctx.NewRetriever(source), source, []auditClaim{{UnverifiedExploitSketch: "routes/a.go:2–3; absent.go:1; ../other.go:1"}}, map[string]bool{}, chunk.NewTokenCounter("", nil))
	if !strings.Contains(text, "2| two") || strings.Contains(text, "private") || strings.Contains(text, "absent.go") {
		t.Fatal(text)
	}
}
