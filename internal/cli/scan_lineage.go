package cli

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/block/codecrucible/internal/auditcore"
	"github.com/block/codecrucible/internal/llm"
	"github.com/block/codecrucible/internal/provenance"
	"github.com/block/codecrucible/internal/sarif"
)

var lineageWriter = func(w io.Writer) io.Writer { return w }

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
		l = provenance.New(m.Execution.RunID, lineageWriter(file))
	}
	l.BestEffort(warnLineage)
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
			if r.Properties != nil {
				single.ProducerID = r.Properties.OriginProducerID
				single.ObservationOffset = r.Properties.OriginOrdinal
			}
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
	base   llm.Client
	ledger *provenance.Ledger
	phase  string
}

func traceClient(base llm.Client, ledger *provenance.Ledger, phase string) llm.Client {
	ledger.BestEffort(warnLineage)
	return &lineageClient{base: base, ledger: ledger, phase: phase}
}
func clientLedger(client llm.Client) *provenance.Ledger {
	for {
		switch c := client.(type) {
		case *lineageClient:
			return c.ledger
		case *recordingClient:
			client = c.next
		default:
			return nil
		}
	}
}
func (c *lineageClient) ChatCompletion(ctx context.Context, req llm.ChatRequest) (*llm.ChatResponse, error) {
	prompt, _ := json.Marshal(req.Messages)
	schema, _ := json.Marshal(req.ResponseSchema)
	p, err := c.ledger.BeginRequest(c.phase, req.Label, auditcore.Producer{RequestedModel: llm.RequestModel(req), PromptFingerprint: fingerprint(prompt), SchemaFingerprint: fingerprint(schema), SourceBundleFingerprint: req.SourceBundleFingerprint, Repairs: req.Repairs})
	if err != nil {
		warnLineage(err)
	}
	response, err := c.base.ChatCompletion(ctx, req)
	e := provenance.Exchange{Label: req.Label, Model: p.RequestedModel, PromptFingerprint: p.PromptFingerprint, SchemaFingerprint: p.SchemaFingerprint, Failed: err != nil}
	if response != nil {
		e.Content = response.Content
		e.FinishReason = response.FinishReason
		if response.Model != "" {
			e.Model = response.Model
		}
	} else {
		response = &llm.ChatResponse{}
	}
	response.ProducerID = p.ResponseID
	if writeErr := c.ledger.CompleteRequest(p, e); writeErr != nil {
		warnLineage(writeErr)
	}
	return response, err
}
func parsedProducer(client llm.Client, response *llm.ChatResponse, content string) (string, error) {
	if response == nil {
		return "", nil
	}
	id := response.ProducerID
	if l := clientLedger(client); l != nil && id != "" && content != response.Content {
		return l.Transform(id, "local-json-repair", content)
	}
	return id, nil
}

func warnLineage(err error) {
	slog.Warn("lineage incomplete; continuing with scan results", "error", err)
}
