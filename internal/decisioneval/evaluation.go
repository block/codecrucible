// Package decisioneval freezes small, labeled source decisions independently
// of scan generation. Synthetic labels test plumbing, not model efficacy.
package decisioneval

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/block/codecrucible/internal/cwe"
	"github.com/block/codecrucible/internal/decision"
)

type Case struct {
	ID            string            `json:"id"`
	Kind          string            `json:"kind"` // evidence or cwe
	LabelOrigin   string            `json:"label_origin"`
	Claim         string            `json:"claim"`
	Fact          string            `json:"required_fact,omitempty"`
	Sources       map[string]string `json:"sources"`
	RelevantPaths []string          `json:"relevant_paths,omitempty"`
	Candidates    []string          `json:"candidates,omitempty"`
	Expected      []string          `json:"expected,omitempty"`
	OriginalCWE   string            `json:"original_cwe,omitempty"`
}

type Result struct {
	Kind                   string            `json:"kind"`
	Expected               map[string]string `json:"expected"`
	OriginalCWE            string            `json:"original_cwe,omitempty"`
	OriginalCorrect        bool              `json:"original_correct"`
	AppropriateAbstentions int               `json:"appropriate_abstentions"`
	ID                     string            `json:"id"`
	LabelOrigin            string            `json:"label_origin"`
	Policy                 string            `json:"policy"`
	Catalog                string            `json:"catalog_version,omitempty"`
	RequestHash            string            `json:"request_hash"`
	Request                decision.Request  `json:"request"`
	Response               decision.Response `json:"response"`
	Error                  string            `json:"error,omitempty"`
	Live                   bool              `json:"live"`
	CandidateCovered       bool              `json:"candidate_covered"`
	Baseline               string            `json:"baseline,omitempty"`
	BaselineCorrect        bool              `json:"baseline_correct"`
	Attempted              int               `json:"attempted"`
	Resolved               int               `json:"resolved"`
	Correct                int               `json:"correct"`
	Incorrect              int               `json:"incorrect"`
	Abstained              int               `json:"abstained"`
	MissedRelevant         int               `json:"missed_relevant"`
	FalseSupport           int               `json:"false_support"`
}

func Prepare(c Case, model string) (Result, map[string]string, error) {
	r := Result{Kind: c.Kind, ID: c.ID, LabelOrigin: c.LabelOrigin, Policy: decision.PolicyVersion}
	if c.ID == "" || c.LabelOrigin == "" || c.Claim == "" || len(c.Sources) == 0 {
		return r, nil, fmt.Errorf("case requires id, label_origin, claim and sources")
	}
	paths := make([]string, 0, len(c.Sources))
	for path := range c.Sources {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	source := []decision.Evidence{}
	for _, path := range paths {
		content := c.Sources[path]
		e, ok := decision.SourceEvidence(path, content, 1, len(strings.Split(strings.TrimSuffix(content, "\n"), "\n")))
		if !ok {
			return r, nil, fmt.Errorf("case %s has invalid source", c.ID)
		}
		source = append(source, e)
	}
	questions, expected := map[string]decision.Question{}, map[string]string{}
	switch c.Kind {
	case "evidence":
		if c.Fact == "" {
			return r, nil, fmt.Errorf("evidence case requires a named required_fact")
		}
		for _, path := range c.RelevantPaths {
			if _, ok := c.Sources[path]; !ok {
				return r, nil, fmt.Errorf("relevant path absent from frozen candidates")
			}
		}
		r.CandidateCovered = true
		for _, e := range source {
			questions[e.ID] = decision.RelevanceQuestion(e.ID, c.Fact)
			expected[e.ID] = "no"
			if contains(c.RelevantPaths, e.Path) {
				expected[e.ID] = "yes"
			}
		}
	case "cwe":
		if len(c.Expected) == 0 {
			return r, nil, fmt.Errorf("CWE case requires expected labels")
		}
		r.Catalog = cwe.Version()
		r.OriginalCWE = c.OriginalCWE
		r.OriginalCorrect = contains(c.Expected, c.OriginalCWE)
		options := map[string]string{"none_of_these": "The root cause is outside these candidates or combines distinct mechanisms", "insufficient_evidence": "The required distinction is not established"}
		for _, id := range c.Candidates {
			e, ok := cwe.Lookup(id)
			if !ok || !e.Mappable() {
				return r, nil, fmt.Errorf("invalid CWE candidate %s", id)
			}
			options[e.ID] = e.Name + " (" + e.Abstraction + ", " + e.Mapping + "). " + e.Description + " Mapping notes: " + e.MappingNotes
		}
		if len(c.Candidates) == 0 {
			return r, nil, fmt.Errorf("CWE case requires frozen candidates")
		}
		for _, label := range c.Expected {
			if _, ok := options[label]; ok {
				r.CandidateCovered = true
			}
		}
		questions["primary_cwe"] = decision.CWEQuestion(options)
		expected["primary_cwe"] = strings.Join(c.Expected, "|")
		baseline := cwe.Candidates(c.Claim, "", 1)
		if len(baseline) > 0 {
			r.Baseline = baseline[0].ID
			r.BaselineCorrect = contains(c.Expected, r.Baseline)
		}
	default:
		return r, nil, fmt.Errorf("unknown case kind %q", c.Kind)
	}
	r.Expected = expected
	r.Request = decision.Request{Model: model, Purpose: c.Kind, State: map[string]any{"claim": c.Claim, "required_fact": c.Fact, "source": source}, Questions: questions}
	data, _ := json.Marshal(r.Request)
	r.RequestHash = decision.Digest(string(data))
	return r, expected, nil
}

func Run(ctx context.Context, c Case, model string, evaluator decision.Evaluator) (Result, error) {
	r, expected, err := Prepare(c, model)
	if err != nil {
		return r, err
	}
	if evaluator == nil {
		return r, nil
	}
	r.Live = true
	r.Attempted = len(expected)
	r.Response, err = evaluator.Evaluate(ctx, r.Request)
	if err != nil {
		r.Error = decision.FailureReason(err)
	}
	for id, label := range expected {
		a, ok := r.Response.Answers[id]
		q := r.Request.Questions[id]
		if !ok || decision.ValidateResponse(decision.Request{Questions: map[string]decision.Question{id: q}}, decision.Response{Model: r.Response.Model, Answers: map[string]decision.Answer{id: a}}) != nil {
			r.Abstained++
			if label == "yes" {
				r.MissedRelevant++
			}
			continue
		}
		prediction := ""
		if q.Type == "noul" {
			if *a.Noul >= .98 {
				prediction = "yes"
			} else if *a.Noul <= .02 {
				prediction = "no"
			}
		} else if decision.Strong(a, a.Choice) {
			prediction = a.Choice
		}
		if prediction == "" || prediction == "insufficient_evidence" || prediction == "none_of_these" {
			r.Abstained++
			if prediction != "" && (contains(strings.Split(label, "|"), prediction) || (prediction == "none_of_these" && !r.CandidateCovered)) {
				r.AppropriateAbstentions++
			}
			if label == "yes" {
				r.MissedRelevant++
			}
			continue
		}
		r.Resolved++
		if contains(strings.Split(label, "|"), prediction) {
			r.Correct++
		} else {
			r.Incorrect++
			if prediction == "yes" {
				r.FalseSupport++
			}
			if label == "yes" {
				r.MissedRelevant++
			}
		}
	}
	return r, ctx.Err()
}

func contains(items []string, value string) bool {
	for _, item := range items {
		if item == value {
			return true
		}
	}
	return false
}
