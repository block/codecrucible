package cli

import (
	"encoding/json"
	"fmt"

	"github.com/block/codecrucible/internal/auditcore"
	"github.com/block/codecrucible/internal/ingest"
	"github.com/block/codecrucible/internal/llm"
	"github.com/block/codecrucible/internal/provenance"
	"github.com/block/codecrucible/internal/sarif"
)

type auditJournal struct {
	attempts  map[string]int
	ledger    *provenance.Ledger
	policy    string
	revisions map[string]string
	accepted  map[string]auditcore.Decision
}

// Excluded candidates remain reconstructable observations with explicit policy
// reasons. Finish gives each one a filtered terminal disposition.
func (j *auditJournal) excludeCandidates(candidates []NewFinding, fileMap ingest.FileMap) error {
	if j == nil || j.ledger == nil {
		return nil
	}
	for _, candidate := range candidates {
		doc := sarif.AssignFindingIDs(buildAuditCandidate(candidate, fileMap))
		doc.ProducerID = candidate.ProducerID
		doc.ObservationOffset = candidate.ProducerOrdinal
		op := fmt.Sprintf("audit-excluded/%s/%d", candidate.ProducerID, candidate.ProducerOrdinal)
		if err := j.ledger.Observe(op, &doc); err != nil {
			return err
		}
		raw, err := json.Marshal(candidate)
		if err != nil {
			return err
		}
		for _, run := range doc.Runs {
			for _, result := range run.Results {
				if err := j.ledger.Discard(op, result.Properties.Provenance.RevisionID, "audit_discovery_disabled", raw); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func newAuditJournal(client llm.Client, doc sarif.SARIFDocument, policy string) *auditJournal {
	j := &auditJournal{attempts: map[string]int{}, ledger: clientLedger(client), policy: policy, revisions: map[string]string{}, accepted: map[string]auditcore.Decision{}}
	if len(doc.Runs) > 0 {
		ids := auditFindingIDs(doc.Runs[0].Results)
		for i, r := range doc.Runs[0].Results {
			if r.Properties != nil && r.Properties.Provenance != nil {
				j.revisions[ids[i]] = r.Properties.Provenance.RevisionID
			}
		}
	}
	return j
}
func (j *auditJournal) attempt(pending []auditClaim, resp *llm.ChatResponse, raw map[string]json.RawMessage, accepted map[string]bool, problem error) error {
	if j == nil || j.ledger == nil {
		return nil
	}
	producer := ""
	if resp != nil {
		producer = resp.ProducerID
	}
	if producer == "" {
		return nil
	}
	if !json.Valid([]byte(resp.Content)) {
		if repaired, changed := llm.RepairJSON(resp.Content); changed && json.Valid([]byte(repaired)) {
			id, err := j.ledger.Transform(producer, "local-json-repair", repaired)
			if err != nil {
				return err
			}
			producer = id
			resp.ProducerID = id
			resp.Content = repaired
		}
	}
	wanted := map[string]bool{}
	for _, c := range pending {
		wanted[c.FindingID] = true
	}
	for id, entry := range raw {
		if !wanted[id] {
			if err := j.ledger.Discard(producer+"/"+auditcore.Digest([]any{id, entry}), producer, "unknown finding identity", entry); err != nil {
				return err
			}
		}
	}
	for _, c := range pending {
		rev := j.revisions[c.FindingID]
		if rev == "" {
			continue
		}
		if j.attempts[c.FindingID] > 0 {
			if _, err := j.ledger.RecordDecision(producer+"/"+c.FindingID+"/retry", c.FindingID, auditcore.Decision{InputRevision: rev, ProducerID: producer, Policy: j.policy, State: "retried"}); err != nil {
				return err
			}
		}
		j.attempts[c.FindingID]++
		d := auditcore.Decision{InputRevision: rev, ProducerID: producer, Policy: j.policy, State: "invalid", Raw: raw[c.FindingID]}
		if problem != nil {
			d.Reasons = []string{problem.Error()}
		}
		if accepted[c.FindingID] {
			d.State = "accepted"
			d.Reasons = nil
			j.accepted[c.FindingID] = d
		}
		if _, err := j.ledger.RecordDecision(producer+"/"+c.FindingID, c.FindingID, d); err != nil {
			return err
		}
	}
	return nil
}
func (j *auditJournal) finish(doc *sarif.SARIFDocument) error {
	if j == nil || j.ledger == nil {
		return nil
	}
	if err := checkpointAudit(j.ledger, doc); err != nil {
		return err
	}
	for _, run := range doc.Runs {
		for _, r := range run.Results {
			p := r.Properties
			if p == nil || p.Provenance == nil {
				continue
			}
			input := j.revisions[p.FindingID]
			if input == "" {
				input = p.Provenance.RevisionID
			}
			d := j.accepted[p.FindingID]
			if d.ProducerID == "" {
				d.ProducerID = p.OriginProducerID
			}
			d.InputRevision = input
			d.Policy = j.policy
			d.Outcome = p.AuditStatus
			d.OutputRevisions = []string{p.Provenance.RevisionID}
			d.Reasons = p.AuditReasons
			d.State = "accepted"
			switch {
			case len(r.Suppressions) > 0:
				d.State = "suppressed"
			case p.AuditStatus == "refined":
				d.State = "refined"
			case p.AuditStatus == "not_audited" || p.AuditStatus == "unverified":
				d.State = "unresolved"
			}
			if _, err := j.ledger.RecordDecision(fmt.Sprintf("%s/final/%s", j.policy, p.FindingID), p.FindingID, d); err != nil {
				return err
			}
		}
	}
	return nil
}
func rawAssessments[T any](items []T, id func(T) string) map[string]json.RawMessage {
	grouped := map[string][]json.RawMessage{}
	for _, a := range items {
		b, _ := json.Marshal(a)
		grouped[id(a)] = append(grouped[id(a)], b)
	}
	out := map[string]json.RawMessage{}
	for id, entries := range grouped {
		if len(entries) == 1 {
			out[id] = entries[0]
		} else {
			out[id], _ = json.Marshal(entries)
		}
	}
	return out
}
