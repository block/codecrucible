// Package provenance records immutable finding observations and revisions.
// It deliberately has no provider configuration or credential-bearing requests.
package provenance

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"sync"

	"github.com/block/codecrucible/internal/sarif"
)

// Event is one versioned JSONL record. Inputs refer to earlier nodes; result
// snapshots are written immediately and are never updated in place.
type Event struct {
	Exchange  *Exchange           `json:"exchange,omitempty"`
	Metadata  *sarif.ScanMetadata `json:"metadata,omitempty"`
	Version   int                 `json:"version"`
	ID        string              `json:"id"`
	RunID     string              `json:"runId"`
	Operation string              `json:"operation"`
	Type      string              `json:"type"`
	Inputs    []string            `json:"inputs,omitempty"`
	FindingID string              `json:"findingId,omitempty"`
	Reason    string              `json:"reason,omitempty"`
	Result    *sarif.SARIFResult  `json:"result,omitempty"`
	Rule      *sarif.SARIFRule    `json:"rule,omitempty"`
}

type Ledger struct {
	mu           sync.Mutex
	err          error
	run          string
	writer       io.Writer
	seen         map[string]string
	observations map[string]bool
}

func New(run string, w io.Writer) *Ledger {
	if w == nil {
		w = io.Discard
	}
	return &Ledger{run: run, writer: w, seen: map[string]string{}, observations: map[string]bool{}}
}
func digest(v any) string {
	b, _ := json.Marshal(v)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
func (l *Ledger) emit(e Event) error {
	if l.err != nil {
		return l.err
	}
	e.Version, e.RunID = 1, l.run
	e.ID = "EV-" + digest([]string{l.run, e.Operation})
	for _, input := range e.Inputs {
		if _, ok := l.seen[input]; !ok {
			return fmt.Errorf("lineage operation %s refers to unknown input %s", e.Operation, input)
		}
	}
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	hash := digest(e)
	if old, ok := l.seen[e.ID]; ok {
		if old != hash {
			return fmt.Errorf("conflicting lineage operation %s", e.Operation)
		}
		return nil
	}
	n, err := l.writer.Write(append(b, '\n'))
	if err == nil && n != len(b)+1 {
		err = io.ErrShortWrite
	}
	if err != nil {
		l.err = fmt.Errorf("writing lineage: %w", err)
		return l.err
	}
	l.seen[e.ID] = hash
	return nil
}

// Observe must run before any merge/filter. Operation identifies the accepted
// response, including chunk/recovery identity. Replay reuses it; a fresh model
// response must have a different operation identity.
func (l *Ledger) Observe(operation string, doc *sarif.SARIFDocument) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	for ri := range doc.Runs {
		run := &doc.Runs[ri]
		rules := map[string]sarif.SARIFRule{}
		for _, r := range run.Tool.Driver.Rules {
			rules[r.ID] = r
		}
		for i := range run.Results {
			r := &run.Results[i]
			op := fmt.Sprintf("%s/observation/%d/%d", operation, ri, i)
			id := "EV-" + digest([]string{l.run, op})
			snapshot := *r
			p := sarif.FindingProperties{}
			if r.Properties != nil {
				p = *r.Properties
			}
			p.Provenance = nil
			snapshot.Properties = &p
			rule := rules[r.RuleID]
			if err := l.emit(Event{Operation: op, Type: "observation", Result: &snapshot, Rule: &rule}); err != nil {
				return err
			}
			p.Provenance = &sarif.FindingProvenance{RunID: l.run, ObservationIDs: []string{id}, RevisionID: id}
			r.Properties = &p
			l.observations[id] = true
		}
	}
	return nil
}

// Checkpoint links an immutable output revision to its input revisions. The
// operation is idempotent for the same snapshot, regardless of output ordering.
func (l *Ledger) Checkpoint(stage string, doc *sarif.SARIFDocument) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	for ri := range doc.Runs {
		run := &doc.Runs[ri]
		rules := map[string]sarif.SARIFRule{}
		for _, r := range run.Tool.Driver.Rules {
			rules[r.ID] = r
		}
		for i := range run.Results {
			r := &run.Results[i]
			if r.Properties == nil || r.Properties.Provenance == nil {
				return fmt.Errorf("%s: finding has no observation", stage)
			}
			p := *r.Properties
			pr := *p.Provenance
			parents := append([]string{}, pr.Parents...)
			if len(parents) == 0 {
				parents = []string{pr.RevisionID}
			}
			sort.Strings(parents)
			snapshot := *r
			p.Provenance = nil
			snapshot.Properties = &p
			op := stage + "/revision/" + digest(struct {
				Observations []string
				Result       sarif.SARIFResult
			}{pr.ObservationIDs, snapshot})
			id := "EV-" + digest([]string{l.run, op})
			if pr.RevisionID == id {
				continue
			}
			rule := rules[r.RuleID]
			kind := "derived_from"
			if len(parents) > 1 {
				kind = "merged_from"
			}
			if err := l.emit(Event{Operation: op, Type: kind, Inputs: parents, FindingID: p.FindingID, Result: &snapshot, Rule: &rule}); err != nil {
				return err
			}
			pr.RevisionID = id
			pr.Parents = nil
			p.Provenance = &pr
			r.Properties = &p
		}
	}
	return nil
}

// Finish accounts for every observation, including candidates removed before
// public finding IDs were assigned. A missing Finish denotes an interrupted run.
func (l *Ledger) Finish(doc sarif.SARIFDocument) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	outputs := map[string][]string{}
	suppressed := map[string]bool{}
	for _, run := range doc.Runs {
		for _, r := range run.Results {
			if r.Properties == nil || r.Properties.Provenance == nil {
				continue
			}
			for _, id := range r.Properties.Provenance.ObservationIDs {
				outputs[id] = append(outputs[id], r.Properties.Provenance.RevisionID)
				suppressed[id] = len(r.Suppressions) > 0
			}
		}
	}
	ids := make([]string, 0, len(l.observations))
	for id := range l.observations {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		kind, reason := "retained", "present in final projection"
		if len(outputs[id]) == 0 {
			kind, reason = "filtered", "removed by post-processing"
		} else if suppressed[id] {
			kind, reason = "suppressed", "retained as a suppressed final finding"
		}
		inputs := append([]string{id}, outputs[id]...)
		if err := l.emit(Event{Operation: "disposition/" + id, Type: kind, Inputs: inputs, Reason: reason}); err != nil {
			return err
		}
	}
	return nil
}

// Metadata records the credential-free scan recipe and source fingerprints.
func (l *Ledger) Metadata(operation string, m *sarif.ScanMetadata) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.emit(Event{Operation: operation, Type: "run", Metadata: m})
}

// Exchange contains model output and fingerprints, never request headers,
// credentials, endpoint query strings, or full prompt contents.
type Exchange struct {
	Label             string `json:"label"`
	Model             string `json:"model"`
	PromptFingerprint string `json:"promptFingerprint"`
	SchemaFingerprint string `json:"schemaFingerprint"`
	Content           string `json:"content,omitempty"`
	FinishReason      string `json:"finishReason,omitempty"`
	Failed            bool   `json:"failed,omitempty"`
}

func (l *Ledger) ModelResponse(operation string, exchange Exchange) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.emit(Event{Operation: operation, Type: "model_response", Exchange: &exchange})
}
