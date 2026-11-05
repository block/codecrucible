package cli

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/block/codecrucible/internal/llm"
	"github.com/block/codecrucible/internal/provenance"
	"github.com/block/codecrucible/internal/sarif"
)

func openLineage(w phaseArtifactWriter, m *sarif.ScanMetadata) (*provenance.Ledger, *os.File, error) {
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, nil, err
	}
	m.Execution.RunID = hex.EncodeToString(nonce[:])
	var file *os.File
	if path := w.Path("lineage"); path != "" {
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			return nil, nil, err
		}
		var err error
		file, err = os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
		if err != nil {
			return nil, nil, err
		}
		if err = file.Chmod(0600); err != nil {
			_ = file.Close()
			return nil, nil, err
		}
	}
	var l *provenance.Ledger
	if file == nil {
		l = provenance.New(m.Execution.RunID, nil)
	} else {
		l = provenance.New(m.Execution.RunID, file)
	}
	if err := l.Metadata("run-start", m); err != nil {
		if file != nil {
			_ = file.Close()
		}
		return nil, nil, fmt.Errorf("starting lineage: %w", err)
	}
	return l, file, nil
}

func checkpointAudit(l *provenance.Ledger, doc *sarif.SARIFDocument) error {
	// Audit may introduce results that have not yet been through presentation.
	// Their public identities must already exist in the recorded revision.
	*doc = sarif.AssignFindingIDs(*doc)
	if len(doc.Runs) == 0 {
		return nil
	}
	for i := range doc.Runs[0].Results {
		r := &doc.Runs[0].Results[i]
		if r.Properties == nil || r.Properties.Provenance == nil {
			single := *doc
			single.Runs = append([]sarif.SARIFRun{}, doc.Runs...)
			single.Runs[0].Results = []sarif.SARIFResult{*r}
			if err := l.Observe(fmt.Sprintf("audit-new/%d", i), &single); err != nil {
				return err
			}
			*r = single.Runs[0].Results[0]
		}
	}
	return l.Checkpoint("audit", doc)
}

// lineageClient records each phase-level response before parsing/retrying it.
// Transport retries with no model output remain the provider client's concern.
type lineageClient struct {
	base     llm.Client
	ledger   *provenance.Ledger
	phase    string
	mu       sync.Mutex
	attempts map[string]int
}

func traceClient(base llm.Client, ledger *provenance.Ledger, phase string) llm.Client {
	return &lineageClient{base: base, ledger: ledger, phase: phase, attempts: map[string]int{}}
}
func (c *lineageClient) ChatCompletion(ctx context.Context, req llm.ChatRequest) (*llm.ChatResponse, error) {
	c.mu.Lock()
	c.attempts[req.Label]++
	attempt := c.attempts[req.Label]
	c.mu.Unlock()
	response, err := c.base.ChatCompletion(ctx, req)
	prompt, _ := json.Marshal(req.Messages)
	schema, _ := json.Marshal(req.ResponseSchema)
	e := provenance.Exchange{Label: req.Label, Model: llm.RequestModel(req), PromptFingerprint: fingerprint(prompt), SchemaFingerprint: fingerprint(schema), Failed: err != nil}
	if response != nil {
		e.Content = response.Content
		e.FinishReason = response.FinishReason
		if response.Model != "" {
			e.Model = response.Model
		}
	}
	if writeErr := c.ledger.ModelResponse(fmt.Sprintf("request/%s/%s/%d", c.phase, req.Label, attempt), e); writeErr != nil {
		return nil, writeErr
	}
	return response, err
}
