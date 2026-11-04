package auditcore

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

const PolicyVersion = "audit-v3/1"

var Questions = []string{"attacker_control", "weakness", "boundary", "unmitigated", "impact"}

type Material struct {
	ID   string `json:"id"`
	Text string `json:"text"`
}
type Coverage struct {
	MaterialID string `json:"material_id"`
	Quote      string `json:"quote"`
}
type Claim struct {
	Evidence   []NamedEvidence `json:"evidence,omitempty"`
	FindingID  string          `json:"finding_id"`
	RevisionID string          `json:"revision_id"`
	Digest     string          `json:"claim_digest"`
	Title      string          `json:"title"`
	Detail     string          `json:"detail"`
	File       string          `json:"file"`
	Start      int             `json:"start_line"`
	End        int             `json:"end_line"`
	CWE        string          `json:"cwe"`
	Severity   float64         `json:"severity"`
	Material   []Material      `json:"material"`
}

func Seal(c Claim) Claim { c.Digest = ""; c.Digest = Digest(c); return c }

type FlowStep struct {
	From     string     `json:"from_expression"`
	To       string     `json:"to_expression"`
	Evidence []Evidence `json:"evidence"`
}

type Assertion struct {
	GuardState    string     `json:"guard_state"`
	ConsumerInput string     `json:"consumer_input_expression"`
	GuardInput    string     `json:"guard_input_expression"`
	Flow          []FlowStep `json:"flow"`
	Kind          string     `json:"kind"`
	Status        string     `json:"status"`
	Statement     string     `json:"statement"`
	Reason        string     `json:"reason"`
	// Subject identifies the concrete value/action. Consumer and Guard describe
	// its actual use and the decisive control; each has separate source anchors.
	Subject          string       `json:"subject_expression"`
	Consumer         string       `json:"consumer_expression"`
	Guard            string       `json:"guard_expression"`
	Evidence         []Evidence   `json:"evidence"`
	ConsumerEvidence []Evidence   `json:"consumer_evidence"`
	GuardEvidence    []Evidence   `json:"guard_evidence"`
	Assumptions      []Assumption `json:"assumptions"`
}
type Assumption struct {
	Runtime  string     `json:"runtime"`
	Version  string     `json:"version"`
	Behavior string     `json:"behavior"`
	Evidence []Evidence `json:"evidence"`
}
type Child struct {
	Title    string     `json:"title"`
	Detail   string     `json:"detail"`
	File     string     `json:"file"`
	Start    int        `json:"start_line"`
	End      int        `json:"end_line"`
	Covers   []Coverage `json:"covers"`
	Evidence []Evidence `json:"evidence"`
}
type Assessment struct {
	CoveredMaterial []Coverage  `json:"covered_material"`
	FindingID       string      `json:"finding_id"`
	RevisionID      string      `json:"revision_id"`
	Digest          string      `json:"claim_digest"`
	Assertions      []Assertion `json:"assertions"`
	Crux            string      `json:"crux"`
	Missing         []Evidence  `json:"missing_evidence"`
	Children        []Child     `json:"children"`
	Summary         string      `json:"summary"`
	Remediation     string      `json:"remediation"`
	RefinedSeverity float64     `json:"refined_severity"`
	SeverityBasis   string      `json:"severity_basis"`
	RefinedCWE      string      `json:"refined_cwe"`
}
type Outcome struct {
	Status     string      `json:"status"`
	Reasons    []string    `json:"reasons,omitempty"`
	Assertions []Assertion `json:"assertions"`
	Crux       string      `json:"crux,omitempty"`
	Policy     string      `json:"policy"`
}

// VerifySource is restricted to pinned, admitted source; callers additionally
// ensure that each cited range was actually present in the request bundle.
type VerifySource func(Evidence) (Evidence, bool)

func ValidIdentity(c Claim, a Assessment) bool {
	return c.FindingID == a.FindingID && c.RevisionID == a.RevisionID && c.Digest == a.Digest
}
func ValidShape(a Assessment) bool {
	seen := map[string]bool{}
	for _, v := range a.Assertions {
		if seen[v.Kind] || !question(v.Kind) || (v.Status != "established" && v.Status != "refuted" && v.Status != "unknown") {
			return false
		}
		seen[v.Kind] = true
	}
	return len(seen) == len(Questions)
}
func question(q string) bool {
	for _, v := range Questions {
		if v == q {
			return true
		}
	}
	return false
}
func checked(in []Evidence, verify VerifySource) []Evidence {
	var out []Evidence
	for _, e := range in {
		if v, ok := verify(e); ok {
			out = append(out, v)
		}
	}
	return out
}

// Evaluate conservatively binds claims and source evidence before computing a
// verdict. Semantic flow remains an attributed model assertion, never a graph fact.
func Evaluate(c Claim, a Assessment, verify VerifySource, assumptionVerifiers ...VerifySource) Outcome {
	verifyAssumption := verify
	if len(assumptionVerifiers) > 0 {
		verifyAssumption = assumptionVerifiers[0]
	}
	out := Outcome{Status: "unverified", Policy: PolicyVersion, Crux: strings.TrimSpace(a.Crux)}
	if !ValidIdentity(c, a) || !ValidShape(a) {
		out.Reasons = []string{"invalid_claim_assessment"}
		out.Crux = "A valid assessment bound to this claim revision is required."
		return out
	}
	states := map[string]string{}
	for _, v := range a.Assertions {
		v.Evidence = checked(v.Evidence, verify)
		v.ConsumerEvidence = checked(v.ConsumerEvidence, verify)
		v.GuardEvidence = checked(v.GuardEvidence, verify)
		for i := range v.Flow {
			v.Flow[i].Evidence = checked(v.Flow[i].Evidence, verify)
		}
		valid := strings.TrimSpace(v.Statement) != "" && strings.TrimSpace(v.Subject) != "" && strings.TrimSpace(v.Reason) != "" && len(v.Evidence) > 0
		if v.Kind == "weakness" {
			anchored := false
			for _, e := range v.Evidence {
				if claimAnchor(c, e) {
					anchored = true
					break
				}
			}
			valid = valid && anchored
		}
		if v.Kind == "impact" || v.Kind == "unmitigated" {
			valid = valid && mentions(v.Evidence, v.Subject) && len(v.ConsumerEvidence) > 0 && mentions(v.ConsumerEvidence, v.Consumer) && mentions(v.ConsumerEvidence, v.ConsumerInput) && follows(v.Subject, v.ConsumerInput, v.Flow)
			guardValid := false
			switch v.GuardState {
			case "blocks", "does_not_block":
				guardValid = len(v.GuardEvidence) > 0 && mentions(v.GuardEvidence, v.Guard) && mentions(v.GuardEvidence, v.GuardInput) && follows(v.Subject, v.GuardInput, v.Flow)
			case "not_found":
				// Absence is an attributed search result, backed by the actual
				// protection point. Never use it as a refutation.
				if v.Status == "established" {
					for _, e := range v.GuardEvidence {
						if claimAnchor(c, e) {
							guardValid = true
							break
						}
					}
				}
			}
			valid = valid && guardValid
			if v.Kind == "unmitigated" && ((v.Status == "refuted" && v.GuardState != "blocks") || (v.Status == "established" && v.GuardState == "blocks")) {
				valid = false
			}
		}
		for i := range v.Assumptions {
			x := &v.Assumptions[i]
			x.Evidence = checked(x.Evidence, verifyAssumption)
			if strings.TrimSpace(x.Runtime) == "" || strings.TrimSpace(x.Version) == "" || strings.TrimSpace(x.Behavior) == "" || len(x.Evidence) == 0 || !mentions(x.Evidence, x.Runtime) || !mentions(x.Evidence, x.Version) {
				valid = false
			}
		}
		if v.Status != "unknown" && !valid {
			out.Reasons = append(out.Reasons, "insufficient_evidence:"+v.Kind)
			v.Status = "unknown"
		}
		states[v.Kind] = v.Status
		out.Assertions = append(out.Assertions, v)
	}
	all := true
	for _, q := range Questions {
		if states[q] != "established" {
			all = false
		}
	}
	// Refuting an impact does not disprove the underlying weakness. Preserve
	// the broad claim unresolved; a separately supported narrower child can stand.
	for _, q := range []string{"attacker_control", "weakness", "boundary", "unmitigated"} {
		if states[q] == "refuted" {
			if !materialCovered(c.Material, a.CoveredMaterial) {
				out.Reasons = append(out.Reasons, "incomplete_claim_coverage")
				out.Crux = "Account for every original assertion before rejecting this claim."
				return out
			}
			out.Status = "rejected"
			out.Reasons = append(out.Reasons, "refuted:"+q)
			return out
		}
	}
	if all && !materialCovered(c.Material, a.CoveredMaterial) {
		out.Reasons = append(out.Reasons, "incomplete_claim_coverage")
		out.Crux = "Account for every original assertion before confirming this claim."
		return out
	}
	if all {
		out.Status = "confirmed"
		out.Crux = ""
		return out
	}
	for _, q := range Questions {
		if states[q] != "established" {
			out.Reasons = append(out.Reasons, states[q]+":"+q)
		}
	}
	if out.Crux == "" {
		out.Crux = "Resolve the unsupported assertions: " + strings.Join(out.Reasons, ", ")
	}
	return out
}

// ValidateChild checks exact correspondence with the original, not an LLM's
// claim that a split is complete. Partial coverage keeps the parent visible.
func ValidateChild(parent Claim, c Child, verify VerifySource) (Child, error) {
	if strings.TrimSpace(c.Title) == "" || strings.TrimSpace(c.Detail) == "" || c.Start < 1 || c.End < c.Start {
		return c, fmt.Errorf("invalid child claim")
	}
	material := map[string]string{}
	for _, m := range parent.Material {
		material[m.ID] = m.Text
	}
	if len(c.Covers) == 0 {
		return c, fmt.Errorf("child has no original claim coverage")
	}
	for _, v := range c.Covers {
		if strings.TrimSpace(v.Quote) == "" || !strings.Contains(material[v.MaterialID], v.Quote) {
			return c, fmt.Errorf("child has invalid material coverage")
		}
	}
	c.Evidence = checked(c.Evidence, verify)
	anchored := false
	for _, e := range c.Evidence {
		if e.File == c.File && e.Start <= c.End && e.End >= c.Start {
			anchored = true
		}
	}
	if !anchored {
		return c, fmt.Errorf("child has no verified primary anchor")
	}
	return c, nil
}
func CompleteCoverage(parent Claim, children []Child) bool {
	if len(children) == 0 {
		return false
	}
	for _, m := range parent.Material {
		text := strings.TrimSpace(m.Text)
		if text == "" {
			continue
		}
		covered := make([]bool, len(text))
		for _, c := range children {
			for _, v := range c.Covers {
				if v.MaterialID != m.ID || strings.TrimSpace(v.Quote) == "" {
					continue
				}
				// A covered assertion must also remain explicit in the visible child.
				if !strings.Contains(c.Title, v.Quote) && !strings.Contains(c.Detail, v.Quote) {
					continue
				}
				at := strings.Index(text, v.Quote)
				if at < 0 {
					continue
				}
				for i := at; i < at+len(v.Quote); i++ {
					covered[i] = true
				}
			}
		}
		for i, ch := range []byte(text) {
			if !covered[i] && ch != ' ' && ch != '\n' && ch != '\r' && ch != '\t' {
				return false
			}
		}
	}
	return true
}

// Source expressions must occur in their evidence; explicit, quote-backed flow
// steps connect renamed values. This checks correspondence, not exploitability.
func mentions(evidence []Evidence, expression string) bool {
	expression = strings.Join(strings.Fields(expression), " ")
	if expression == "" {
		return false
	}
	for _, e := range evidence {
		text := strings.Join(strings.Fields(e.Quote), " ")
		for offset := 0; offset < len(text); {
			at := strings.Index(text[offset:], expression)
			if at < 0 {
				break
			}
			at += offset
			end := at + len(expression)
			first, _ := utf8.DecodeRuneInString(expression)
			last, _ := utf8.DecodeLastRuneInString(expression)
			before, after := rune(0), rune(0)
			if at > 0 {
				before, _ = utf8.DecodeLastRuneInString(text[:at])
			}
			if end < len(text) {
				after, _ = utf8.DecodeRuneInString(text[end:])
			}
			ident := func(r rune) bool { return unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_' || r == '$' }
			if (!ident(first) || !ident(before)) && (!ident(last) || !ident(after)) {
				return true
			}
			offset = at + 1
		}
	}
	return false
}
func follows(from, to string, steps []FlowStep) bool {
	if from == "" || to == "" {
		return false
	}
	seen := map[string]bool{from: true}
	for i := 0; i <= len(steps); i++ {
		if seen[to] {
			return true
		}
		changed := false
		for _, s := range steps {
			if seen[s.From] && !seen[s.To] && mentions(s.Evidence, s.From) && mentions(s.Evidence, s.To) {
				seen[s.To] = true
				changed = true
			}
		}
		if !changed {
			return false
		}
	}
	return false
}

func materialCovered(material []Material, coverage []Coverage) bool {
	for _, m := range material {
		if strings.TrimSpace(m.Text) == "" {
			continue
		}
		ok := false
		for _, c := range coverage {
			if c.MaterialID == m.ID && strings.TrimSpace(c.Quote) == strings.TrimSpace(m.Text) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	return true
}

func claimAnchor(c Claim, e Evidence) bool {
	matches := func(file string, start, end int) bool {
		return file != "" && file == e.File && start > 0 && e.Start <= max(start, end) && e.End >= start
	}
	if matches(c.File, c.Start, c.End) {
		return true
	}
	for _, a := range c.Evidence {
		if matches(a.Evidence.File, a.Evidence.Start, a.Evidence.End) {
			return true
		}
	}
	return false
}
