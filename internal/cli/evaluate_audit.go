package cli

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"strings"

	"github.com/block/codecrucible/internal/sarif"
	"github.com/spf13/cobra"
)

// Labels are independently adjudicated frozen-input cases. Child claims can be
// selected by parent and original source anchor when their run IDs differ.
type auditEvalCase struct {
	FindingID     string `json:"finding_id"`
	ParentID      string `json:"parent_id"`
	File          string `json:"file"`
	Line          int    `json:"line"`
	ClaimContains string `json:"claim_contains"`
	Weakness      string `json:"weakness"`
	Impact        string `json:"impact"`
}
type auditEvalPair struct {
	Left      string `json:"left"`
	Right     string `json:"right"`
	Duplicate bool   `json:"duplicate"`
}
type auditEvalLabels struct {
	Cases []auditEvalCase `json:"cases"`
	Pairs []auditEvalPair `json:"pairs"`
}
type auditEvalRate struct {
	Count int     `json:"count"`
	Total int     `json:"total"`
	Rate  float64 `json:"rate"`
	Low   float64 `json:"lower95"`
	High  float64 `json:"upper95"`
}
type auditEvalReport struct {
	Cases                      int                    `json:"cases"`
	RecallMisses               int                    `json:"recallMisses"`
	Recall                     auditEvalRate          `json:"recall"`
	Missing                    int                    `json:"missing"`
	Statuses                   map[string]int         `json:"statuses"`
	InvalidConfirmed           auditEvalRate          `json:"invalidConfirmed"`
	UnsupportedImpactConfirmed auditEvalRate          `json:"unsupportedImpactConfirmed"`
	PositiveSuppressed         auditEvalRate          `json:"knownPositiveSuppressed"`
	DuplicatePrecision         auditEvalRate          `json:"duplicatePrecision"`
	AuditModels                []sarif.ModelExecution `json:"auditModels,omitempty"`
}

func rate(count, total int) auditEvalRate {
	r := auditEvalRate{Count: count, Total: total}
	if total == 0 {
		return r
	}
	n := float64(total)
	p := float64(count) / n
	z := 1.95996398454
	d := 1 + z*z/n
	c := (p + z*z/(2*n)) / d
	h := z * math.Sqrt(p*(1-p)/n+z*z/(4*n*n)) / d
	r.Rate = p
	r.Low = math.Max(0, c-h)
	r.High = math.Min(1, c+h)
	return r
}
func scoreAudit(doc sarif.SARIFDocument, labels auditEvalLabels) (auditEvalReport, error) {
	out := auditEvalReport{Cases: len(labels.Cases), Statuses: map[string]int{}}
	var results []sarif.SARIFResult
	for _, run := range doc.Runs {
		results = append(results, run.Results...)
		if run.Properties != nil && run.Properties.CodeCrucible != nil {
			out.AuditModels = append(out.AuditModels, run.Properties.CodeCrucible.Execution.Phases["audit"].Models...)
		}
	}
	invalid, ic, unsupported, uc, positive, ps := 0, 0, 0, 0, 0, 0
	byID := map[string]sarif.SARIFResult{}
	for _, r := range results {
		if r.Properties != nil {
			byID[r.Properties.FindingID] = r
		}
	}
	for _, c := range labels.Cases {
		if c.Weakness != "valid" && c.Weakness != "invalid" && c.Weakness != "unknown" {
			return out, fmt.Errorf("invalid weakness label %q", c.Weakness)
		}
		var matches []sarif.SARIFResult
		for _, r := range results {
			p := r.Properties
			if p == nil {
				continue
			}
			if c.FindingID != "" && p.FindingID != c.FindingID {
				continue
			}
			if c.ParentID != "" && p.ParentFindingID != c.ParentID {
				continue
			}
			if c.File != "" {
				if len(r.Locations) == 0 || r.Locations[0].PhysicalLocation.ArtifactLocation.URI != c.File {
					continue
				}
				reg := r.Locations[0].PhysicalLocation.Region
				if c.Line > 0 && (reg == nil || reg.StartLine != c.Line) {
					continue
				}
			}
			if c.ClaimContains != "" && !strings.Contains(p.TechnicalDetails, c.ClaimContains) {
				continue
			}
			matches = append(matches, r)
		}
		if len(matches) > 1 {
			return out, fmt.Errorf("ambiguous label for %s/%s", c.FindingID, c.ParentID)
		}
		active, suppressed := false, false
		if len(matches) == 0 {
			out.Missing++
		} else {
			p := matches[0].Properties
			out.Statuses[p.AuditStatus]++
			suppressed = len(matches[0].Suppressions) > 0
			active = !suppressed
		}
		if c.Weakness == "invalid" {
			invalid++
			if active {
				ic++
			}
		}
		if c.Impact == "unsupported" {
			unsupported++
			if active {
				uc++
			}
		}
		if c.Weakness == "valid" {
			positive++
			if len(matches) == 0 {
				out.RecallMisses++
			} else if suppressed {
				ps++
			}
		}
	}
	tp, reported := 0, 0
	for _, pair := range labels.Pairs {
		r, ok := byID[pair.Left]
		if !ok || r.Properties == nil {
			continue
		}
		found := r.Properties.DuplicateOf == pair.Right
		for _, id := range r.Properties.SemanticDuplicates {
			found = found || id == pair.Right
		}
		if other, ok := byID[pair.Right]; ok && other.Properties != nil {
			found = found || other.Properties.DuplicateOf == pair.Left
			for _, id := range other.Properties.SemanticDuplicates {
				found = found || id == pair.Left
			}
		}
		if found {
			reported++
			if pair.Duplicate {
				tp++
			}
		}
	}
	out.InvalidConfirmed = rate(ic, invalid)
	out.UnsupportedImpactConfirmed = rate(uc, unsupported)
	out.PositiveSuppressed = rate(ps, positive)
	out.Recall = rate(positive-ps-out.RecallMisses, positive)
	out.DuplicatePrecision = rate(tp, reported)
	return out, nil
}
func newEvaluateAuditCommand() *cobra.Command {
	var labelsPath string
	cmd := &cobra.Command{Use: "evaluate-audit SARIF", Short: "Score a frozen audit against independently adjudicated labels", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		var doc sarif.SARIFDocument
		var labels auditEvalLabels
		b, err := os.ReadFile(args[0])
		if err != nil {
			return err
		}
		if err = json.Unmarshal(b, &doc); err != nil {
			return err
		}
		b, err = os.ReadFile(labelsPath)
		if err != nil {
			return err
		}
		if err = json.Unmarshal(b, &labels); err != nil {
			return err
		}
		report, err := scoreAudit(doc, labels)
		if err != nil {
			return err
		}
		b, err = json.MarshalIndent(report, "", "  ")
		if err == nil {
			fmt.Fprintln(cmd.OutOrStdout(), string(b))
		}
		return err
	}}
	cmd.Flags().StringVar(&labelsPath, "labels", "", "JSON labels file (cases and duplicate pairs)")
	_ = cmd.MarkFlagRequired("labels")
	return cmd
}
