// Package auditcore defines provider-independent claim and evidence records.
// A verified quote proves source fidelity, not the model's interpretation.
package auditcore

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

func Digest(v any) string {
	b, _ := json.Marshal(v)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

type Producer struct {
	RequestID               string `json:"requestId"`
	AttemptID               string `json:"attemptId"`
	ResponseID              string `json:"responseId"`
	Operation               string `json:"operation"`
	Phase                   string `json:"phase"`
	RequestedModel          string `json:"requestedModel"`
	PromptFingerprint       string `json:"promptFingerprint"`
	SchemaFingerprint       string `json:"schemaFingerprint"`
	SourceBundleFingerprint string `json:"sourceBundleFingerprint,omitempty"`
	Repairs                 string `json:"repairs,omitempty"`
}

type Decision struct {
	InputRevision   string          `json:"inputRevision"`
	ProducerID      string          `json:"producerId,omitempty"`
	Policy          string          `json:"policy"`
	State           string          `json:"state"`
	Outcome         string          `json:"outcome,omitempty"`
	Reasons         []string        `json:"reasons,omitempty"`
	Raw             json.RawMessage `json:"raw,omitempty"`
	OutputRevisions []string        `json:"outputRevisions,omitempty"`
}

type Relationship struct {
	Kind       string     `json:"kind"`
	From       string     `json:"from"`
	To         string     `json:"to"`
	Reason     string     `json:"reason"`
	ProducerID string     `json:"producerId,omitempty"`
	Evidence   []Evidence `json:"evidence,omitempty"`
}

type Evidence struct {
	File        string `json:"file"`
	Start       int    `json:"start_line"`
	End         int    `json:"end_line"`
	Quote       string `json:"quote"`
	Fingerprint string `json:"fingerprint,omitempty"`
	Validation  string `json:"validation,omitempty"`
}

type PairJudgment struct {
	LeftID        string     `json:"left_id"`
	LeftDigest    string     `json:"left_digest"`
	RightID       string     `json:"right_id"`
	RightDigest   string     `json:"right_digest"`
	Judgment      string     `json:"judgment"`
	Reason        string     `json:"reason"`
	CauseEvidence []Evidence `json:"cause_evidence"`
	FixEvidence   []Evidence `json:"fix_evidence"`
}

type NamedEvidence struct {
	Kind     string   `json:"kind"`
	Evidence Evidence `json:"evidence"`
}
