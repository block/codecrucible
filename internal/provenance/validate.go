package provenance

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"

	"github.com/block/codecrucible/internal/sarif"
)

type Validation struct {
	RunID        string   `json:"runId"`
	Events       int      `json:"events"`
	Observations int      `json:"observations"`
	Decisions    int      `json:"decisions"`
	Complete     bool     `json:"complete"`
	Unresolved   []string `json:"unresolved,omitempty"`
}

// Validate accepts v1 and v2 ledgers. Backward references enforce acyclic
// derivation; an interrupted run is reported without inventing dispositions.
func Validate(r io.Reader, final *sarif.SARIFDocument) (Validation, error) {
	var report Validation
	nodes := map[string]Event{}
	observations := map[string]bool{}
	terminal := map[string]bool{}
	dispositions := map[string][]string{}
	relationships := map[string]map[string][]string{}
	dec := json.NewDecoder(r)
	for {
		var e Event
		err := dec.Decode(&e)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return report, fmt.Errorf("decode lineage event %d: %w", report.Events+1, err)
		}
		if e.Version != 1 && e.Version != 2 {
			return report, fmt.Errorf("unsupported lineage version %d", e.Version)
		}
		if report.RunID == "" {
			report.RunID = e.RunID
		}
		if e.RunID != report.RunID {
			return report, fmt.Errorf("mixed lineage runs")
		}
		if e.ID != "EV-"+digest([]string{e.RunID, e.Operation}) {
			return report, fmt.Errorf("invalid event identity %s", e.ID)
		}
		if _, ok := nodes[e.ID]; ok {
			return report, fmt.Errorf("repeated operation %s", e.Operation)
		}
		for _, id := range e.Inputs {
			if _, ok := nodes[id]; !ok {
				return report, fmt.Errorf("%s has unknown/forward input %s", e.Operation, id)
			}
		}
		switch e.Type {
		case "observation":
			if e.Version >= 2 && len(e.Inputs) != 1 {
				return report, fmt.Errorf("observation %s lacks producer", e.ID)
			}
			observations[e.ID] = true
			report.Observations++
		case "decision":
			if e.Decision == nil || !contains(e.Inputs, e.Decision.InputRevision) || (e.Decision.ProducerID != "" && !contains(e.Inputs, e.Decision.ProducerID)) {
				return report, fmt.Errorf("decision %s has unbound inputs", e.ID)
			}
			for _, id := range e.Decision.OutputRevisions {
				if !contains(e.Inputs, id) {
					return report, fmt.Errorf("decision %s has unbound output", e.ID)
				}
			}
			report.Decisions++
		case "relationship":
			if e.Relationship == nil || e.Relationship.From == e.Relationship.To || !contains(e.Inputs, e.Relationship.From) || !contains(e.Inputs, e.Relationship.To) {
				return report, fmt.Errorf("invalid relationship %s", e.ID)
			}
			rel := e.Relationship
			if relationships[rel.Kind] == nil {
				relationships[rel.Kind] = map[string][]string{}
			}
			graph := relationships[rel.Kind]
			if reachable(graph, rel.To, rel.From, map[string]bool{}) {
				return report, fmt.Errorf("cyclic %s relationship", rel.Kind)
			}
			graph[rel.From] = append(graph[rel.From], rel.To)

		case "retained", "suppressed", "filtered":
			if len(e.Inputs) == 0 || !observations[e.Inputs[0]] || terminal[e.Inputs[0]] {
				return report, fmt.Errorf("invalid disposition %s", e.ID)
			}
			terminal[e.Inputs[0]] = true
			dispositions[e.Inputs[0]] = append([]string{}, e.Inputs[1:]...)
		}
		if e.Operation == "run-complete" {
			report.Complete = true
		}
		nodes[e.ID] = e
		report.Events++
	}
	for id := range observations {
		if !terminal[id] {
			report.Unresolved = append(report.Unresolved, id)
		}
	}
	sort.Strings(report.Unresolved)
	if report.Complete && len(report.Unresolved) > 0 {
		return report, fmt.Errorf("completed run has %d undisposed observations", len(report.Unresolved))
	}
	if final != nil {
		canonical := sarif.ReviewPresentation(*final)
		for _, run := range canonical.Runs {
			for _, result := range run.Results {
				if result.Properties == nil || result.Properties.Provenance == nil {
					return report, fmt.Errorf("final result lacks provenance")
				}
				p := result.Properties.Provenance
				e, ok := nodes[p.RevisionID]
				if !ok || p.RunID != report.RunID || e.FindingID != result.Properties.FindingID {
					return report, fmt.Errorf("final finding %s cannot reconcile", result.Properties.FindingID)
				}
				for _, id := range p.ObservationIDs {
					if !observations[id] {
						return report, fmt.Errorf("unknown original observation %s", id)
					}
				}
				if e.Result == nil || e.Rule == nil {
					return report, fmt.Errorf("revision %s lacks a result snapshot", e.ID)
				}
				projected := sarif.ReviewPresentation(sarif.SARIFDocument{Runs: []sarif.SARIFRun{{Tool: sarif.SARIFTool{Driver: sarif.SARIFDriver{Rules: []sarif.SARIFRule{*e.Rule}}}, Results: []sarif.SARIFResult{*e.Result}}}}).Runs[0].Results[0]
				if projectionDigest(projected) != projectionDigest(result) {
					return report, fmt.Errorf("final finding %s differs from its recorded revision", result.Properties.FindingID)
				}
				if report.Complete {
					for _, id := range p.ObservationIDs {
						if !contains(dispositions[id], p.RevisionID) {
							return report, fmt.Errorf("final revision %s has no observation disposition", p.RevisionID)
						}
					}
				}

			}
		}
	}
	return report, nil
}
func contains(values []string, want string) bool {
	for _, v := range values {
		if v == want {
			return true
		}
	}
	return false
}

func reachable(graph map[string][]string, from, to string, seen map[string]bool) bool {
	if from == to {
		return true
	}
	if seen[from] {
		return false
	}
	seen[from] = true
	for _, next := range graph[from] {
		if reachable(graph, next, to, seen) {
			return true
		}
	}
	return false
}

func projectionDigest(r sarif.SARIFResult) string {
	if r.Properties != nil {
		p := *r.Properties
		p.Provenance = nil
		r.Properties = &p
	}
	return digest(r)
}
