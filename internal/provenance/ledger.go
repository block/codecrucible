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

	"github.com/block/codecrucible/internal/auditcore"
	"github.com/block/codecrucible/internal/sarif"
)

// Event is one versioned JSONL record. Inputs refer to earlier nodes; result
// snapshots are written immediately and are never updated in place.
type Event struct {
	Artifact     json.RawMessage         `json:"artifact,omitempty"`
	Producer     *auditcore.Producer     `json:"producer,omitempty"`
	Decision     *auditcore.Decision     `json:"decision,omitempty"`
	Relationship *auditcore.Relationship `json:"relationship,omitempty"`
	Exchange     *Exchange               `json:"exchange,omitempty"`
	Metadata     *sarif.ScanMetadata     `json:"metadata,omitempty"`
	Version      int                     `json:"version"`
	ID           string                  `json:"id"`
	RunID        string                  `json:"runId"`
	Operation    string                  `json:"operation"`
	Type         string                  `json:"type"`
	Inputs       []string                `json:"inputs,omitempty"`
	FindingID    string                  `json:"findingId,omitempty"`
	Reason       string                  `json:"reason,omitempty"`
	Result       *sarif.SARIFResult      `json:"result,omitempty"`
	Rule         *sarif.SARIFRule        `json:"rule,omitempty"`
}

type Ledger struct {
	mu           sync.Mutex
	err          error
	run          string
	writer       io.Writer
	seen         map[string]string
	observations map[string]bool
	attempts     map[string]int
}

func New(run string, w io.Writer) *Ledger {
	if w == nil {
		w = io.Discard
	}
	return &Ledger{run: run, writer: w, seen: map[string]string{}, observations: map[string]bool{}, attempts: map[string]int{}}
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
	e.Version, e.RunID = 2, l.run
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
			producer := doc.ProducerID
			if producer == "" {
				producer = l.id("operation/" + operation)
				if err := l.emit(Event{Operation: "operation/" + operation, Type: "operation", Reason: "imported or deterministic result"}); err != nil {
					return err
				}
			}
			op := fmt.Sprintf("%s/observation/%d/%d", producer, ri, i+doc.ObservationOffset)
			id := "EV-" + digest([]string{l.run, op})
			snapshot := *r
			p := sarif.FindingProperties{}
			if r.Properties != nil {
				p = *r.Properties
			}
			p.Provenance = nil
			snapshot.Properties = &p
			rule := rules[r.RuleID]
			if err := l.emit(Event{Operation: op, Type: "observation", Inputs: []string{producer}, Result: &snapshot, Rule: &rule}); err != nil {
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
				if _, seen := suppressed[id]; !seen {
					suppressed[id] = true
				}
				suppressed[id] = suppressed[id] && len(r.Suppressions) > 0
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
		sort.Strings(outputs[id])
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

func (l *Ledger) id(operation string) string { return "EV-" + digest([]string{l.run, operation}) }

// BeginRequest persists identity before the transport runs, including failures
// that never produce a response. Counters belong to the run, not client wrappers.
func (l *Ledger) BeginRequest(phase, label string, p auditcore.Producer) (auditcore.Producer, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	base := "request/" + phase + "/" + label
	l.attempts[base]++
	p.Operation = fmt.Sprintf("%s/%d", base, l.attempts[base])
	p.Phase = phase
	p.RequestID = l.id(p.Operation + "/request")
	p.AttemptID = l.id(p.Operation + "/start")
	p.ResponseID = l.id(p.Operation + "/response")
	var inputs []string
	if p.Repairs != "" {
		inputs = append(inputs, p.Repairs)
	}
	if err := l.emit(Event{Operation: p.Operation + "/request", Type: "request", Inputs: inputs, Producer: &p}); err != nil {
		return p, err
	}
	return p, l.emit(Event{Operation: p.Operation + "/start", Type: "model_request", Inputs: []string{p.RequestID}, Producer: &p})
}
func (l *Ledger) CompleteRequest(p auditcore.Producer, e Exchange) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.emit(Event{Operation: p.Operation + "/response", Type: "model_response", Inputs: []string{p.AttemptID}, Producer: &p, Exchange: &e})
}

// Transform records a deterministic parse/repair operation without inventing a
// second model response. Its identity is stable when the operation is replayed.
func (l *Ledger) Transform(parent, kind string, content any) (string, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	op := kind + "/" + digest([]any{parent, content})
	return l.id(op), l.emit(Event{Operation: op, Type: "operation", Inputs: []string{parent}, Reason: kind})
}
func (l *Ledger) RecordDecision(operation, finding string, d auditcore.Decision) (string, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	inputs := []string{d.InputRevision}
	if d.ProducerID != "" {
		inputs = append(inputs, d.ProducerID)
	}
	inputs = append(inputs, d.OutputRevisions...)
	op := "decision/" + operation
	return l.id(op), l.emit(Event{Operation: op, Type: "decision", FindingID: finding, Inputs: inputs, Decision: &d})
}
func (l *Ledger) RecordRelationship(operation string, r auditcore.Relationship) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	switch r.Kind {
	case "derived_from", "split_from", "merged_from", "duplicate_of":
	default:
		return fmt.Errorf("unknown relationship %q", r.Kind)
	}
	inputs := []string{r.From, r.To}
	if r.ProducerID != "" {
		inputs = append(inputs, r.ProducerID)
	}
	return l.emit(Event{Operation: "relationship/" + operation, Type: "relationship", Inputs: inputs, Relationship: &r})
}

// Child gives a derived claim a revision without manufacturing a new first-pass
// observation. The original grouped observation remains its ancestor.
func (l *Ledger) Child(operation, producer string, parent sarif.FindingProvenance, doc *sarif.SARIFDocument) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(doc.Runs) != 1 || len(doc.Runs[0].Results) != 1 {
		return fmt.Errorf("child must contain one result")
	}
	r := &doc.Runs[0].Results[0]
	p := sarif.FindingProperties{}
	if r.Properties != nil {
		p = *r.Properties
	}
	p.Provenance = nil
	snapshot := *r
	snapshot.Properties = &p
	inputs := []string{parent.RevisionID}
	if producer != "" {
		inputs = append(inputs, producer)
	}
	op := "split/" + operation
	var rule sarif.SARIFRule
	for _, v := range doc.Runs[0].Tool.Driver.Rules {
		if v.ID == r.RuleID {
			rule = v
			break
		}
	}
	if err := l.emit(Event{Operation: op, Type: "split_from", Inputs: inputs, FindingID: p.FindingID, Result: &snapshot, Rule: &rule}); err != nil {
		return err
	}
	p.Provenance = &sarif.FindingProvenance{RunID: l.run, ObservationIDs: append([]string{}, parent.ObservationIDs...), RevisionID: l.id(op)}
	r.Properties = &p
	return nil
}

func (l *Ledger) Artifact(operation string, v any) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return l.emit(Event{Operation: operation, Type: "artifact", Artifact: b})
}

func (l *Ledger) Discard(operation, producer, reason string, raw json.RawMessage) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.emit(Event{Operation: "discard/" + operation, Type: "discarded", Inputs: []string{producer}, Reason: reason, Artifact: raw})
}
