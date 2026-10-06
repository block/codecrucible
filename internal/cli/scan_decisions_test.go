package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/block/codecrucible/internal/chunk"
	"github.com/block/codecrucible/internal/config"
	"github.com/block/codecrucible/internal/decision"
	"github.com/block/codecrucible/internal/ingest"
	"github.com/block/codecrucible/internal/llm"
	"github.com/block/codecrucible/internal/sarif"
	"github.com/block/codecrucible/internal/tokenestimate"
	"github.com/block/codecrucible/internal/usage"
)

type evaluateFunc func(context.Context, decision.Request) (decision.Response, error)

func (f evaluateFunc) Evaluate(ctx context.Context, r decision.Request) (decision.Response, error) {
	return f(ctx, r)
}
func strongAnswer(q decision.Question, choice string) decision.Answer {
	one := 1.0
	p := map[string]float64{}
	for key := range q.Criteria.(map[string]string) {
		p[key] = 0
	}
	p[choice] = 1
	return decision.Answer{Type: "choice", Choice: choice, Confidence: &one, Probabilities: p}
}
func answersFor(req decision.Request, choices map[string]string) decision.Response {
	out := decision.Response{Model: decision.Model, Answers: map[string]decision.Answer{}}
	for id, q := range req.Questions {
		choice := choices[id]
		if choice == "" {
			switch id {
			case "reachability", "attacker_control":
				if choices["coverage"] == "sufficient" {
					choice = "established"
				}
			case "operation", "impact":
				if choices["coverage"] == "sufficient" {
					choice = "supported"
				}
			case "mitigation":
				if choices["verdict"] == "supported" {
					choice = "ineffective"
				}
				if choices["verdict"] == "blocked" {
					choice = "effective"
				}
			default:
				if strings.HasPrefix(id, "assertion_") {
					choice = choices["claim_support"]
				}
			}
		}
		if q.Type == "noul" {
			value := 0.0
			if id == "blocking_present" && choices["verdict"] == "blocked" {
				value = 1
			}
			if choices[strings.TrimSuffix(id, "_signal")] == "present" {
				value = 1
			}
			if choice == "yes" {
				value = 1
			}
			out.Answers[id] = decision.Answer{Type: "noul", Noul: &value}
			continue
		}
		if q.Type == "score" {
			value, confidence := 0.0, 1.0
			probabilities := map[string]float64{"0": 1, "1": 0, "2": 0}
			if choice == "related" {
				value = 2
				probabilities = map[string]float64{"0": 0, "1": 0, "2": 1}
			}
			legend := map[string]string{}
			for i, level := range q.Criteria.([]string) {
				legend[fmt.Sprint(i)] = level
			}
			out.Answers[id] = decision.Answer{Type: "score", Score: &value, Confidence: &confidence, Probabilities: probabilities, Legend: legend}
			continue
		}
		if choice == "" {
			choice = "insufficient_evidence"
		}
		out.Answers[id] = strongAnswer(q, choice)
	}
	return out
}
func decisionFixture(t *testing.T) (*scanDecisions, sarif.SARIFDocument) {
	t.Helper()
	files := map[string]string{"a.go": "package main\nfunc read(input string) {\n execute(input)\n}\n", "b.go": "package main\nfunc read(input string) {\n if !allowed(input) { return }\n execute(input)\n}\n"}
	doc := sarif.Build(sarif.AnalysisResult{SecurityIssues: []sarif.SecurityIssue{{Issue: "Unchecked input", FilePath: "a.go", StartLine: 3, EndLine: 3, Severity: 8, TechnicalDetails: "Input reaches execute without an allowlist."}, {Issue: "Unchecked input", FilePath: "b.go", StartLine: 4, EndLine: 4, Severity: 8, TechnicalDetails: "Input reaches execute without an allowlist."}}}, sarif.FileMap(files), sarif.BuilderConfig{})
	d := &scanDecisions{auditPolicySupported: true, cfg: config.Decisions{Audit: "active", Review: "active", FeatureDetection: "off", SmartChunking: "off"}, files: files, graph: map[string][]string{}, recorder: &decision.Recorder{}}
	return d, doc
}
func TestJevAuditSelectsEvidenceWithoutChangingFindings(t *testing.T) {
	for _, mode := range []string{"active", "shadow"} {
		d, doc := decisionFixture(t)
		d.cfg.Audit = mode
		d.files["page.html"] = `<script src="a.go"></script>`
		calls := 0
		d.recorder.Client = evaluateFunc(func(_ context.Context, req decision.Request) (decision.Response, error) {
			calls++
			if req.Purpose != "audit" {
				t.Fatal("unexpected stage")
			}
			answers := map[string]decision.Answer{}
			for id, q := range req.Questions {
				if q.Type != "noul" {
					t.Fatal("audit still requests verdicts")
				}
				one := 1.0
				answers[id] = decision.Answer{Type: "noul", Noul: &one}
			}
			return decision.Response{Model: decision.Model, Answers: answers}, nil
		})
		before, _ := json.Marshal(doc)
		err := d.selectAuditEvidence(context.Background(), doc)
		after, _ := json.Marshal(doc)
		if err != nil || string(before) != string(after) || calls == 0 {
			t.Fatalf("findings changed or evidence unused: %v calls=%d", err, calls)
		}
		if (len(d.auditEvidence) > 0) != (mode == "active") {
			t.Fatal("wrong evidence mode behavior")
		}
	}
}
func TestJevIncompleteAndShadowPreserveFindings(t *testing.T) {
	d, doc := decisionFixture(t)
	d.cfg.Audit = "shadow"
	d.recorder.Client = evaluateFunc(func(_ context.Context, req decision.Request) (decision.Response, error) {
		return answersFor(req, map[string]string{"coverage": "sufficient", "verdict": "supported", "blocking_evidence": "none"}), nil
	})
	before, _ := json.Marshal(doc)
	err := d.selectAuditEvidence(context.Background(), doc)
	after, _ := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("shadow altered output")
	}
	d.cfg.Audit = "active"
	d.evidenceIndex = nil
	delete(d.files, "a.go")
	d.files["b.go"] = strings.Repeat("source\n", 10000)
	d.recorder.Client = evaluateFunc(func(context.Context, decision.Request) (decision.Response, error) {
		t.Fatal("incomplete evidence should fall back without a decision")
		return decision.Response{}, nil
	})
	err = d.selectAuditEvidence(context.Background(), doc)
	after, _ = json.Marshal(doc)
	if err != nil || len(doc.Runs[0].Results) != 2 || string(before) != string(after) {
		t.Fatal("incomplete evidence suppressed a finding")
	}
}
func TestJevReviewRetainsUncertainFindingsAndEvidenceProvenance(t *testing.T) {
	d, doc := decisionFixture(t)
	d.recorder.Client = evaluateFunc(func(_ context.Context, req decision.Request) (decision.Response, error) {
		return answersFor(req, map[string]string{"claim_support": "contradicted"}), nil
	})
	reviewed, err := d.reviewFindings(context.Background(), doc)
	if err != nil {
		t.Fatal(err)
	}
	if len(reviewed.Runs[0].Results) != 2 {
		t.Fatal("review silently suppressed a finding")
	}
	for _, r := range reviewed.Runs[0].Results {
		if r.Properties.DecisionReview.Status != "contradicted" || len(r.Properties.DecisionReview.EvidenceIDs) == 0 {
			t.Fatal("missing explicit validation requirement")
		}
	}
	presented := sarif.ReviewPresentation(reviewed)
	if strings.Contains(presented.Runs[0].Results[0].Message.Text, "manual validation") || presented.Runs[0].Results[0].Properties.DecisionReview.Status != "contradicted" {
		t.Fatal("review uncertainty must remain in properties")
	}
	report, _ := json.Marshal(d.recorder.Report())
	if strings.Contains(string(report), "execute(input)") {
		t.Fatal("raw source in decision artifact")
	}
}
func TestJevFeatureSelectionRequiresCompleteCoverage(t *testing.T) {
	loader := llm.NewPromptLoader(fstest.MapFS{"analysis_sections.yaml": &fstest.MapFile{Data: []byte("sections:\n  auth:\n    title: Authentication\n    features: [auth]\n    content: Check authentication\n  storage:\n    title: Storage\n    features: [database]\n    content: Check storage\n  always:\n    title: Always\n    content: Check inputs\n")}})
	d, _ := decisionFixture(t)
	d.cfg.FeatureDetection = "active"
	d.recorder.Client = evaluateFunc(func(_ context.Context, req decision.Request) (decision.Response, error) {
		return answersFor(req, map[string]string{"feature_0": "present", "feature_1": "absent"}), nil
	})
	features, handled, err := d.featureDetection(context.Background(), loader)
	if err != nil || !handled || !reflect.DeepEqual(features, []string{"auth"}) {
		t.Fatalf("features=%v handled=%v err=%v", features, handled, err)
	}
	d.files["huge.go"] = strings.Repeat("important source", 3000)
	features, handled, err = d.featureDetection(context.Background(), loader)
	if err != nil || !handled || len(features) != 2 {
		t.Fatal("partial source pruned a feature")
	}
	d.cfg.FeatureDetection = "shadow"
	_, handled, err = d.featureDetection(context.Background(), loader)
	if err != nil || handled {
		t.Fatal("shadow replaced feature detection")
	}
}
func TestJevGroupingPreservesDependenciesAndFileCoverage(t *testing.T) {
	d, _ := decisionFixture(t)
	d.cfg.SmartChunking = "active"
	d.cfg.DependencyGrouping = true
	d.files = map[string]string{"route/a.go": "package a\nfunc customerHandler() { customerService() }\n" + strings.Repeat("// route behavior\n", 20), "storage/b.go": "package b\nfunc customerService() { customerHandler() }\n" + strings.Repeat("// storage behavior\n", 20), "unrelated/c.go": "package c\n" + strings.Repeat("// unrelated behavior\n", 20)}
	d.graph = map[string][]string{"route/a.go": {"unrelated/c.go"}}
	d.recorder.Client = evaluateFunc(func(_ context.Context, req decision.Request) (decision.Response, error) {
		choices := map[string]string{}
		for id := range req.Questions {
			choices[id] = "related"
		}
		return answersFor(req, choices), nil
	})
	graph, err := d.smartGrouping(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(graph["route/a.go"], ","), "unrelated/c.go") {
		t.Fatal("discarded deterministic dependency")
	}
	if !strings.Contains(strings.Join(graph["route/a.go"], ","), "storage/b.go") {
		t.Fatal("semantic relationship not grouped")
	}
	counter := tokenestimate.New(tokenestimate.Model{}, nil)
	chunks, err := chunk.NewChunker(counter, nil).Chunk(ingest.FlattenResult{FileMap: ingest.FileMap(d.files)}, 700, &chunk.ChunkOptions{ImportGraph: graph})
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, c := range chunks {
		if c.Tokens > 700 {
			t.Fatal("chunk exceeded budget")
		}
		for _, p := range c.Paths {
			seen[p] = true
		}
	}
	if len(seen) != len(d.files) {
		t.Fatalf("lost files: %v", seen)
	}
	d.cfg.SmartChunking = "shadow"
	d.cfg.DependencyGrouping = false
	baseline := map[string][]string{"one": {"two"}}
	got, err := d.smartGrouping(context.Background(), baseline)
	if err != nil || !reflect.DeepEqual(got, baseline) {
		t.Fatal("shadow changed chunking")
	}
}

func TestOptionalJevCLIUsesOriginalPipelineUnlessEnabled(t *testing.T) {
	for _, tc := range []struct {
		name                      string
		flags                     []string
		auditCalls, decisionCalls int
		jevAudit, failure, dryRun bool
	}{
		{name: "disabled", auditCalls: 1},
		{name: "dependency control without key", flags: []string{"--dependency-grouping"}, auditCalls: 1},
		{name: "enabled", flags: []string{"--jev", "--jev-review", "active", "--jev-cwe-mapping", "shadow"}, auditCalls: 1, decisionCalls: 2, jevAudit: true},
		{name: "per-stage overrides", flags: []string{"--jev-audit", "active", "--jev-review", "off"}, auditCalls: 1},
		{name: "skip audit", flags: []string{"--jev-review", "active", "--skip-audit"}, decisionCalls: 1},
		{name: "review only", flags: []string{"--jev-review", "active"}, auditCalls: 1, decisionCalls: 1},
		{name: "CWE mapping only", flags: []string{"--jev-cwe-mapping", "shadow"}, auditCalls: 1, decisionCalls: 1},
		{name: "deduplication only", flags: []string{"--jev-deduplication", "active"}, auditCalls: 1},
		{name: "unavailable", flags: []string{"--jev-review", "active", "--jev-cwe-mapping", "shadow"}, auditCalls: 1, decisionCalls: 2, failure: true},
		{name: "dry run without key", flags: []string{"--jev-audit", "shadow", "--dry-run"}, dryRun: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			oldV := v
			t.Cleanup(func() { v = oldV })
			t.Setenv("TYPESAFE_API_KEY", "test-jev-key")
			if tc.dryRun || tc.name == "dependency control without key" {
				t.Setenv("TYPESAFE_API_KEY", "")
			}
			analysisCalls, auditCalls, decisionCalls := 0, 0, 0
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.HasSuffix(r.URL.Path, "systemone") {
					decisionCalls++
					if tc.failure {
						w.WriteHeader(http.StatusServiceUnavailable)
						return
					}
					var req decision.Request
					if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
						t.Error(err)
						return
					}
					// Decode criteria into typed questions as the real client sends JSON maps.
					for id, q := range req.Questions {
						if q.Type != "choice" {
							continue
						}
						raw := q.Criteria.(map[string]any)
						typed := map[string]string{}
						for k, value := range raw {
							typed[k] = value.(string)
						}
						q.Criteria = typed
						req.Questions[id] = q
					}
					response := answersFor(req, map[string]string{"coverage": "sufficient", "verdict": "supported", "blocking_evidence": "none", "claim_support": "supported"})
					input, output := 20, 4
					response.Usage = decision.TokenUsage{Input: &input, Output: &output}
					_ = json.NewEncoder(w).Encode(response)
					return
				}
				var req struct {
					Model    string        `json:"model"`
					Messages []llm.Message `json:"messages"`
				}
				if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
					t.Error(err)
					return
				}
				content := `{"security_issues":[{"issue":"Missing authorization","file_path":"src/main.go","start_line":3,"end_line":3,"severity":8,"cwe_id":"CWE-862","technical_details":"The handler accesses a resource without checking ownership."}],"public_api_routes":[]}`
				if req.Model == "jev-test-audit" {
					auditCalls++
					content = `{"audited_findings":[{"finding_id":"` + requestedClaims(t, llm.ChatRequest{Messages: req.Messages})[0].FindingID + `","original_issue":"Missing authorization","file_path":"src/main.go","start_line":3,"end_line":3,"verdict":"confirmed","confidence":0.9,"refined_severity":8,"refined_technical_details":"Missing ownership check.","justification":"Visible source evidence.","blocking_code":""}],"new_findings":[],"audit_summary":"checked"}`
				} else {
					analysisCalls++
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"model": req.Model, "choices": []any{map[string]any{"message": map[string]any{"content": content}, "finish_reason": "stop"}}, "usage": map[string]int{"prompt_tokens": 10, "completion_tokens": 2}})
			}))
			defer srv.Close()
			dir := createTestRepo(t)
			out := filepath.Join(t.TempDir(), "scan.sarif")
			cfgPath := filepath.Join(t.TempDir(), "config.yaml")
			cfg := fmt.Sprintf("provider: openai\nmodel: jev-test-analysis\nopenai-api-key: test-key\nbase-url: %s\ncontext-limit: 100000\nmax-output-tokens: 1024\nphases:\n  audit:\n    model: jev-test-audit\ndecisions:\n  retries: 0\n  base-url: %s/v1/systemone\n", srv.URL, srv.URL)
			if err := os.WriteFile(cfgPath, []byte(cfg), 0600); err != nil {
				t.Fatal(err)
			}
			cmd := NewRootCommand()
			prompts, err := filepath.Abs("../../prompts/default")
			if err != nil {
				t.Fatal(err)
			}
			args := []string{"--config", cfgPath, "scan", dir, "--prompts-dir", prompts, "--output", out, "--max-cost", "0"}
			args = append(args, tc.flags...)
			cmd.SetArgs(args)
			if err := cmd.Execute(); err != nil {
				t.Fatal(err)
			}
			if tc.dryRun {
				if analysisCalls != 0 || auditCalls != 0 || decisionCalls != 0 {
					t.Fatal("dry run made requests")
				}
				return
			}
			if auditCalls != tc.auditCalls || decisionCalls != tc.decisionCalls {
				t.Fatalf("requests: audit=%d Jev=%d; wanted audit=%d Jev=%d", auditCalls, decisionCalls, tc.auditCalls, tc.decisionCalls)
			}
			data, err := os.ReadFile(out)
			if err != nil {
				t.Fatal(err)
			}
			var doc sarif.SARIFDocument
			if err := json.Unmarshal(data, &doc); err != nil {
				t.Fatal(err)
			}
			if analysisCalls != 1 || len(doc.Runs[0].Results) != 1 {
				t.Fatal("analysis or findings changed")
			}
			if tc.jevAudit {
				if doc.Runs[0].Results[0].Properties.AuditStatus != "confirmed" {
					t.Fatal("generative audit was bypassed")
				}
				data, err = os.ReadFile(strings.TrimSuffix(out, ".sarif") + ".usage.json")
				if err != nil {
					t.Fatal(err)
				}
				var report usage.Report
				if err = json.Unmarshal(data, &report); err != nil {
					t.Fatal(err)
				}
				if report.Phases["decision.cwe-mapping"].Attempts != 1 || report.Phases["decision.review"].Attempts != 1 {
					t.Fatal("Jev usage absent from whole scan ledger")
				}
			} else if len(tc.flags) == 0 {
				if _, err := os.Stat(strings.TrimSuffix(out, ".sarif") + ".decisions.json"); !os.IsNotExist(err) {
					t.Fatal("disabled scan wrote decision artifact")
				}
			}
		})
	}
}

func TestJevPreservesCustomAuditPolicy(t *testing.T) {
	d, doc := decisionFixture(t)
	d.auditPolicySupported = false
	d.recorder.Client = evaluateFunc(func(context.Context, decision.Request) (decision.Response, error) {
		t.Fatal("custom audit bypassed without prompt-set opt-in")
		return decision.Response{}, nil
	})
	before, _ := json.Marshal(doc)
	err := d.selectAuditEvidence(context.Background(), doc)
	after, _ := json.Marshal(doc)
	if err != nil || string(before) != string(after) {
		t.Fatal("custom audit changed")
	}
}

func TestJevGroupingKeepsSuccessfulBatchesAfterFailure(t *testing.T) {
	for _, mode := range []string{"active", "shadow"} {
		t.Run(mode, func(t *testing.T) {
			d, _ := decisionFixture(t)
			d.cfg.SmartChunking = mode
			d.files = map[string]string{}
			for i := 0; i < 8; i++ {
				d.files[fmt.Sprintf("file%d.go", i)] = "package app\nfunc customerHandler() { customerService() }\n"
			}
			baseline := map[string][]string{"baseline.go": {"required.go"}}
			original, _ := json.Marshal(baseline)
			calls := 0
			accepted := map[string][]string{}
			d.recorder.Client = evaluateFunc(func(_ context.Context, req decision.Request) (decision.Response, error) {
				calls++
				if calls == 2 {
					return decision.Response{}, errors.New("unavailable")
				}
				choices := map[string]string{}
				for id, q := range req.Questions {
					choices[id] = "related"
					// The pair's paths are part of the question, not inferred from samples.
					text := q.Instructions.(string)
					a := strings.Index(text, "Should ") + len("Should ")
					names := strings.SplitN(text[a:], " share an analysis chunk", 2)[0]
					pair := strings.SplitN(names, " and ", 2)
					accepted[pair[0]] = append(accepted[pair[0]], pair[1])
				}
				return answersFor(req, choices), nil
			})
			graph, err := d.smartGrouping(context.Background(), baseline)
			if err != nil || calls < 3 {
				t.Fatalf("stopped after failed batch: calls=%d err=%v", calls, err)
			}
			if mode == "shadow" {
				if !reflect.DeepEqual(graph, baseline) {
					t.Fatal("shadow mutated grouping")
				}
				return
			}
			for path, deps := range accepted {
				for _, dep := range deps {
					if !strings.Contains(strings.Join(graph[path], ","), dep) {
						t.Fatalf("lost successful hint %s -> %s", path, dep)
					}
				}
			}
			if len(graph["baseline.go"]) != 1 {
				t.Fatal("lost baseline dependency")
			}
			after, _ := json.Marshal(baseline)
			if string(original) != string(after) {
				t.Fatal("mutated baseline")
			}
		})
	}
}

func TestJevGroupingKeepsValidAnswersWithinFailedBatch(t *testing.T) {
	for _, mode := range []string{"active", "shadow"} {
		t.Run(mode, func(t *testing.T) {
			d, _ := decisionFixture(t)
			d.cfg.SmartChunking = mode
			d.files = map[string]string{}
			for _, p := range []string{"a.go", "b.go", "c.go"} {
				d.files[p] = "package app\nfunc customerHandler() { customerService() }\n"
			}
			baseline := map[string][]string{"baseline.go": {"required.go"}}
			d.recorder.Client = evaluateFunc(func(_ context.Context, req decision.Request) (decision.Response, error) {
				if len(req.Questions) != 3 {
					t.Fatalf("expected three pairs, got %d", len(req.Questions))
				}
				response := answersFor(req, map[string]string{"pair_0": "related", "pair_1": "related", "pair_2": "related"})
				delete(response.Answers, "pair_1")
				invalid := response.Answers["pair_2"]
				invalid.Legend = nil
				response.Answers["pair_2"] = invalid
				return response, errors.New("remaining pairs unavailable")
			})
			graph, err := d.smartGrouping(context.Background(), baseline)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "active" {
				if !hasGroupingEdge(graph, "a.go", "b.go") || hasGroupingEdge(graph, "a.go", "c.go") || hasGroupingEdge(graph, "b.go", "c.go") {
					t.Fatalf("must use only the valid independent hint: %+v", graph)
				}
			} else if !reflect.DeepEqual(graph, baseline) {
				t.Fatal("shadow changed grouping")
			}
			outcomes := d.recorder.Report().Outcomes["smart-chunking"]
			if outcomes["pairs_unavailable"] != 2 || outcomes["pairs_evaluated"] != 1 || outcomes["edges_accepted"] != 1 {
				t.Fatalf("partial batch accounting is wrong: %+v", outcomes)
			}
		})
	}
}
