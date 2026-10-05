package cli

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/block/codecrucible/internal/decision"
	"github.com/block/codecrucible/internal/sarif"
)

func dedupFixture() (*scanDecisions, sarif.SARIFDocument) {
	d, _ := classificationFixture()
	d.cfg.CWEMapping, d.cfg.Deduplication = "off", "active"
	d.files["query.go"] = "package app\nfunc query(input string) {\n sql := \"SELECT * FROM records WHERE id = \" + input\n db.Query(sql)\n shell(input)\n}\n"
	doc := sarif.WithFindingIDs(sarif.Build(sarif.AnalysisResult{SecurityIssues: []sarif.SecurityIssue{
		{Issue: "A SQL injection", FilePath: "query.go", StartLine: 3, EndLine: 3, TechnicalDetails: "SQL constructed by concatenating input", CWEID: "CWE-89", Severity: 9},
		{Issue: "B Query injection", FilePath: "query.go", StartLine: 4, EndLine: 4, TechnicalDetails: "The same concatenated SQL reaches db.Query", CWEID: "CWE-89", Severity: 8},
		{Issue: "C Shell injection", FilePath: "query.go", StartLine: 5, EndLine: 5, TechnicalDetails: "A separate shell operation receives input", CWEID: "CWE-78", Severity: 7},
	}}, sarif.FileMap(d.files), sarif.BuilderConfig{}))
	return d, doc
}

func duplicateAnswer(req decision.Request, relationship string) decision.Response {
	anchor := "none"
	for id := range req.Questions["shared_root"].Criteria.(map[string]string) {
		if id != "none" {
			anchor = id
			break
		}
	}
	return answersFor(req, map[string]string{"relationship": relationship, "shared_root": anchor})
}

func TestDedupSharedRouterDoesNotCreateCandidates(t *testing.T) {
	d, doc := decisionFixture(t)
	d.cfg.Deduplication = "active"
	d.cfg.MaxCalls = 10
	d.files["router.go"] = "package main\nfunc router() { mount() }"
	for i := range doc.Runs[0].Results {
		doc.Runs[0].Results[i].CodeFlows = sarif.BuildCodeFlows([]sarif.CodePathStep{{FilePath: "router.go", StartLine: 2, EndLine: 2, Message: "Shared registration"}}, sarif.FileMap(d.files))
	}
	doc = sarif.WithFindingIDs(doc)
	d.recorder.Client = evaluateFunc(func(context.Context, decision.Request) (decision.Response, error) {
		t.Fatal("shared router consumed dedup budget")
		return decision.Response{}, nil
	})
	out, err := d.deduplicateFindings(context.Background(), doc)
	if err != nil || !reflect.DeepEqual(out, doc) {
		t.Fatal("distinct findings changed")
	}
}

func TestDedupSharedHelperSurvivesCandidateFiltering(t *testing.T) {
	d, doc := decisionFixture(t)
	d.cfg.Deduplication = "active"
	d.cfg.MaxCalls = 1
	d.files["helper.go"] = "package app\nfunc helper(input string) { execute(input) }"
	for i := range doc.Runs[0].Results {
		path := doc.Runs[0].Results[i].Locations[0].PhysicalLocation.ArtifactLocation.URI
		doc.Runs[0].Results[i].CodeFlows = sarif.BuildCodeFlows([]sarif.CodePathStep{{FilePath: path, StartLine: 3, EndLine: 3, Message: "Caller"}, {FilePath: "helper.go", StartLine: 2, EndLine: 2, Message: "Shared defective operation"}}, sarif.FileMap(d.files))
	}
	calls := 0
	d.recorder.Client = evaluateFunc(func(_ context.Context, req decision.Request) (decision.Response, error) {
		calls++
		return duplicateAnswer(req, "duplicate"), nil
	})
	out, err := d.deduplicateFindings(context.Background(), doc)
	if err != nil || calls != 1 || len(out.Runs[0].Results) != 1 {
		t.Fatalf("shared helper starved: %d calls, %v", calls, err)
	}
}

func TestSemanticDedupDirectComparisonsPreserveRecords(t *testing.T) {
	for _, mode := range []string{"active", "shadow"} {
		t.Run(mode, func(t *testing.T) {
			d, doc := dedupFixture()
			d.cfg.Deduplication = mode
			before, _ := json.Marshal(doc)
			calls := 0
			d.recorder.Client = evaluateFunc(func(_ context.Context, r decision.Request) (decision.Response, error) {
				calls++
				state := r.State.(map[string]any)
				left := state["left"].(map[string]any)["finding"].(string)
				right := state["right"].(map[string]any)["finding"].(string)
				if !strings.HasPrefix(left, "A SQL") {
					t.Fatal("inferred a transitive cluster")
				}
				if strings.HasPrefix(right, "C Shell") {
					return duplicateAnswer(r, "distinct"), nil
				}
				return duplicateAnswer(r, "duplicate"), nil
			})
			out, err := d.deduplicateFindings(context.Background(), doc)
			if err != nil {
				t.Fatal(err)
			}
			if calls != 2 {
				t.Fatalf("expected direct A-B and A-C comparisons, got %d", calls)
			}
			if mode == "shadow" {
				if !reflect.DeepEqual(doc, out) || d.recorder.Report().Outcomes["deduplication"]["proposed_merge"] != 1 {
					t.Fatal("shadow changed findings or missed proposal")
				}
			} else {
				if len(out.Runs[0].Results) != 2 {
					t.Fatal("wrong merge count")
				}
				a := out.Runs[0].Results[0]
				if a.Properties.FindingID != doc.Runs[0].Results[0].Properties.FindingID || len(a.Locations) != 2 {
					t.Fatal("lost identity or affected location")
				}
				if len(a.Properties.Deduplicated) != 1 || !reflect.DeepEqual(a.Properties.Deduplicated[0].Result, doc.Runs[0].Results[1]) {
					t.Fatal("lost duplicate original record")
				}
				if a.Properties.Deduplicated[0].Rule.ID != doc.Runs[0].Results[1].RuleID {
					t.Fatal("lost duplicate rule")
				}
				counts := d.recorder.Report().Outcomes["deduplication"]
				if counts["input_findings"] != 3 || counts["output_findings"] != 2 || counts["merged"] != 1 {
					t.Fatal("unreconciled finding flow")
				}
				view := sarif.ReviewPresentation(out)
				if !strings.Contains(view.Runs[0].Tool.Driver.Rules[0].Help.Text, "Consolidated finding") {
					t.Fatal("merge hidden from reviewer")
				}
			}
			after, _ := json.Marshal(doc)
			if string(before) != string(after) {
				t.Fatal("mutated original evidence")
			}
		})
	}
}

func TestSemanticDedupConservativeFailures(t *testing.T) {
	for _, kind := range []string{"provider", "uncertain", "overlap", "low_probability", "missing_anchor", "foreign_anchor", "missing_source", "off"} {
		t.Run(kind, func(t *testing.T) {
			d, doc := dedupFixture()
			if kind == "missing_source" {
				d.files = nil
			}
			if kind == "off" {
				d.cfg.Deduplication = "off"
			}
			calls := 0
			d.recorder.Client = evaluateFunc(func(_ context.Context, req decision.Request) (decision.Response, error) {
				calls++
				if kind == "provider" {
					return decision.Response{}, errors.New("unavailable")
				}
				out := duplicateAnswer(req, "duplicate")
				switch kind {
				case "overlap":
					out = duplicateAnswer(req, "overlap")
				case "uncertain":
					out = duplicateAnswer(req, "insufficient_evidence")
				case "low_probability":
					a := out.Answers["relationship"]
					a.Probabilities["duplicate"] = .7
					out.Answers["relationship"] = a
				case "missing_anchor":
					out.Answers["shared_root"] = strongAnswer(req.Questions["shared_root"], "none")
				case "foreign_anchor":
					out.Answers["shared_root"] = strongAnswer(req.Questions["shared_root"], "invented")
				}
				return out, nil
			})
			out, err := d.deduplicateFindings(context.Background(), doc)
			if err != nil || !reflect.DeepEqual(out, doc) {
				t.Fatal("lost/changed findings on non-actionable decision")
			}
			if (kind == "missing_source" || kind == "off") && calls != 0 {
				t.Fatal("unnecessary requests")
			}
		})
	}
}

func TestSemanticDedupRequiresSharedSourceAndRespectsBudget(t *testing.T) {
	d, doc := dedupFixture()
	d.cfg.MaxCalls = 1
	calls := 0
	d.recorder.Client = evaluateFunc(func(_ context.Context, req decision.Request) (decision.Response, error) {
		calls++
		return duplicateAnswer(req, "distinct"), nil
	})
	out, err := d.deduplicateFindings(context.Background(), doc)
	if err != nil || calls != 1 || len(out.Runs[0].Results) != 3 {
		t.Fatal("pair budget not respected")
	}

	d, doc = decisionFixture(t) // Identical prose in different operations/files.
	d.cfg.Deduplication, d.cfg.MaxCalls = "active", 128
	d.recorder.Client = evaluateFunc(func(context.Context, decision.Request) (decision.Response, error) {
		t.Fatal("same prose is not a shared root cause")
		return decision.Response{}, nil
	})
	out, err = d.deduplicateFindings(context.Background(), doc)
	if err != nil || len(out.Runs[0].Results) != 2 {
		t.Fatal("distinct operations merged")
	}
}

func TestClassificationStagesRespectCancellation(t *testing.T) {
	for _, stage := range []string{"mapping", "dedup"} {
		d, doc := dedupFixture()
		d.cfg.CWEMapping = "active"
		ctx, cancel := context.WithCancel(context.Background())
		d.recorder.Client = evaluateFunc(func(context.Context, decision.Request) (decision.Response, error) {
			cancel()
			return decision.Response{}, ctx.Err()
		})
		var err error
		if stage == "mapping" {
			_, err = d.mapCWEs(ctx, doc)
		} else {
			_, err = d.deduplicateFindings(ctx, doc)
		}
		cancel()
		if !errors.Is(err, context.Canceled) {
			t.Fatal("swallowed cancellation")
		}
	}
}
