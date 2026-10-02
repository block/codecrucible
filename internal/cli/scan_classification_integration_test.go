package cli

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/block/codecrucible/internal/decision"
	"github.com/block/codecrucible/internal/sarif"
	"github.com/block/codecrucible/internal/usage"
)

func TestClassificationCLIArtifactsAndUsage(t *testing.T) {
	for _, mode := range []string{"active", "shadow"} {
		t.Run(mode, func(t *testing.T) {
			oldV := v
			t.Cleanup(func() { v = oldV })
			t.Setenv("TYPESAFE_API_KEY", "test-key")
			d, doc := dedupFixture()
			mappingCalls, dedupCalls := 0, 0
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.HasSuffix(r.URL.Path, "systemone") {
					var req decision.Request
					if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
						t.Error(err)
						w.WriteHeader(400)
						return
					}
					for id, q := range req.Questions {
						options := map[string]string{}
						for k, value := range q.Criteria.(map[string]any) {
							options[k] = value.(string)
						}
						q.Criteria = options
						req.Questions[id] = q
					}
					var response decision.Response
					if _, ok := req.Questions["primary_cwe"]; ok {
						mappingCalls++
						choice := "CWE-89"
						if strings.HasPrefix(req.State.(map[string]any)["finding"].(string), "C Shell") {
							choice = "CWE-78"
						}
						response = answersFor(req, map[string]string{"primary_cwe": choice})
					} else {
						dedupCalls++
						right := req.State.(map[string]any)["right"].(map[string]any)["finding"].(string)
						relation := "duplicate"
						if strings.HasPrefix(right, "C Shell") {
							relation = "distinct"
						}
						response = duplicateAnswer(req, relation)
					}
					input, output := 50, 10
					response.Usage = decision.TokenUsage{Input: &input, Output: &output}
					_ = json.NewEncoder(w).Encode(response)
					return
				}
				var issues []sarif.SecurityIssue
				for _, result := range doc.Runs[0].Results {
					var title string
					for _, rule := range doc.Runs[0].Tool.Driver.Rules {
						if rule.ID == result.RuleID {
							title = rule.ShortDescription.Text
						}
					}
					location := result.Locations[0].PhysicalLocation
					severity := 9.0
					if strings.HasPrefix(title, "B") {
						severity = 8
					}
					if strings.HasPrefix(title, "C") {
						severity = 7
					}
					issues = append(issues, sarif.SecurityIssue{Issue: title, FilePath: location.ArtifactLocation.URI, StartLine: location.Region.StartLine, EndLine: location.Region.EndLine, Severity: severity, CWEID: "CWE-79", TechnicalDetails: result.Message.Text})
				}
				content, _ := json.Marshal(sarif.AnalysisResult{SecurityIssues: issues})
				_ = json.NewEncoder(w).Encode(map[string]any{"model": "classification-test", "choices": []any{map[string]any{"message": map[string]any{"content": string(content)}, "finish_reason": "stop"}}, "usage": map[string]int{"prompt_tokens": 100, "completion_tokens": 50}})
			}))
			defer srv.Close()
			repo, artifacts := t.TempDir(), t.TempDir()
			if err := os.WriteFile(filepath.Join(repo, "query.go"), []byte(d.files["query.go"]), 0600); err != nil {
				t.Fatal(err)
			}
			cfgPath := filepath.Join(t.TempDir(), "config.yaml")
			cfg := fmt.Sprintf("provider: openai\nmodel: classification-test\nopenai-api-key: test\nbase-url: %s\ncontext-limit: 100000\nmax-output-tokens: 4096\ndecisions:\n  retries: 0\n  base-url: %s/v1/systemone\n", srv.URL, srv.URL)
			if err := os.WriteFile(cfgPath, []byte(cfg), 0600); err != nil {
				t.Fatal(err)
			}
			outPath := filepath.Join(artifacts, "final.sarif")
			cmd := NewRootCommand()
			prompts, err := filepath.Abs("../../prompts/default")
			if err != nil {
				t.Fatal(err)
			}
			cmd.SetArgs([]string{"--config", cfgPath, "scan", repo, "--prompts-dir", prompts, "--skip-feature-detection", "--skip-audit", "--output", outPath, "--phase-output-dir", artifacts, "--max-cost", "0", "--jev-cwe-mapping", mode, "--jev-deduplication", mode})
			if err := cmd.Execute(); err != nil {
				t.Fatal(err)
			}
			if mappingCalls != 3 || dedupCalls != 2 {
				t.Fatalf("requests mapping=%d dedup=%d", mappingCalls, dedupCalls)
			}
			for _, stage := range []string{"analysis", "cwe-mapping", "deduplication", "final"} {
				data, err := os.ReadFile(filepath.Join(artifacts, stage+".sarif"))
				if err != nil {
					t.Fatal(err)
				}
				var got sarif.SARIFDocument
				if err := json.Unmarshal(data, &got); err != nil {
					t.Fatal(err)
				}
				want := 3
				if mode == "active" && (stage == "deduplication" || stage == "final") {
					want = 2
				}
				if len(got.Runs[0].Results) != want {
					t.Fatalf("%s count %d, want %d", stage, len(got.Runs[0].Results), want)
				}
				if stage == "final" && mode == "active" {
					p := got.Runs[0].Results[0].Properties
					if p.DecisionCWE == nil || !p.DecisionCWE.Applied || len(p.Deduplicated) != 1 || p.Deduplicated[0].Result.Properties.DecisionCWE == nil {
						t.Fatal("lost classification or duplicate provenance")
					}
				}
			}
			data, err := os.ReadFile(filepath.Join(artifacts, "usage.json"))
			if err != nil {
				t.Fatal(err)
			}
			var ledger usage.Report
			if err := json.Unmarshal(data, &ledger); err != nil {
				t.Fatal(err)
			}
			if ledger.Phases["decision.cwe-mapping"].Attempts != 3 || ledger.Phases["decision.deduplication"].Attempts != 2 {
				t.Fatal("new requests not accounted")
			}
			data, err = os.ReadFile(filepath.Join(artifacts, "decisions.json"))
			if err != nil {
				t.Fatal(err)
			}
			var report decision.Report
			if err := json.Unmarshal(data, &report); err != nil {
				t.Fatal(err)
			}
			if report.Outcomes["deduplication"]["input_findings"] != 3 {
				t.Fatal("missing outcome counters")
			}
		})
	}
}
