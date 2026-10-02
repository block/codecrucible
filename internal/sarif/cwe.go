package sarif

import (
	"crypto/sha256"
	"fmt"
	"strings"

	"github.com/block/codecrucible/internal/cwe"
)

type CWEAssignment struct{ ID, Source string }

// ApplyCWEAssignments updates individual findings without modifying a shared
// rule, changing finding IDs, or re-running CWE-dependent deduplication.
func ApplyCWEAssignments(doc SARIFDocument, assignments map[string]CWEAssignment) SARIFDocument {
	doc.Runs = append([]SARIFRun(nil), doc.Runs...)
	for i := range doc.Runs {
		run := &doc.Runs[i]
		run.Results = append([]SARIFResult(nil), run.Results...)
		run.Tool.Driver.Rules = append([]SARIFRule(nil), run.Tool.Driver.Rules...)
		run.Taxonomies = append([]SARIFTaxonomy(nil), run.Taxonomies...)
		rules := map[string]SARIFRule{}
		for _, rule := range run.Tool.Driver.Rules {
			rules[rule.ID] = rule
		}
		for j := range run.Results {
			r := &run.Results[j]
			if r.Properties == nil {
				continue
			}
			a, ok := assignments[r.Properties.FindingID]
			if !ok {
				continue
			}
			e, ok := cwe.Lookup(a.ID)
			if !ok || !e.Mappable() {
				continue
			}
			rule, ok := rules[r.RuleID]
			if !ok || CWEForRule(rule) == e.ID {
				continue
			}
			props := *r.Properties
			props.CWEChanges = append(append([]CWEChange(nil), props.CWEChanges...), CWEChange{Original: CWEForRule(rule), Assigned: e.ID, Source: a.Source})
			r.Properties = &props
			base := rule.ID
			for nonce := 0; ; nonce++ {
				sum := sha256.Sum256([]byte(fmt.Sprintf("%s:%s:%s:%d", base, props.FindingID, e.ID, nonce)))
				rule.ID = fmt.Sprintf("%s-cwe-%x", base, sum[:8])
				if _, exists := rules[rule.ID]; !exists {
					break
				}
			}
			properties := map[string]any{}
			for k, v := range rule.Properties {
				properties[k] = v
			}
			var tags []string
			add := func(tag string) {
				if !strings.HasPrefix(strings.ToLower(tag), "external/cwe/") {
					tags = append(tags, tag)
				}
			}
			switch ts := properties["tags"].(type) {
			case []string:
				for _, t := range ts {
					add(t)
				}
			case []any:
				for _, t := range ts {
					if s, ok := t.(string); ok {
						add(s)
					}
				}
			}
			properties["tags"] = append(tags, "external/cwe/"+strings.ToLower(e.ID))
			rule.Properties = properties
			var relationships []SARIFRelationship
			for _, rel := range rule.Relationships {
				if rel.Target.ToolComponent.Name != "CWE" {
					relationships = append(relationships, rel)
				}
			}
			rule.Relationships = append(relationships, SARIFRelationship{Target: SARIFRelationshipTarget{ID: e.ID, ToolComponent: SARIFToolComponentRef{Name: "CWE"}}, Kinds: []string{"superset"}})
			rules[rule.ID] = rule
			run.Tool.Driver.Rules = append(run.Tool.Driver.Rules, rule)
			r.RuleID = rule.ID
			ensureCWETaxon(run, e)
		}
		used := map[string]bool{}
		for _, r := range run.Results {
			used[r.RuleID] = true
		}
		var kept []SARIFRule
		for _, r := range run.Tool.Driver.Rules {
			if used[r.ID] {
				kept = append(kept, r)
			}
		}
		if kept != nil {
			run.Tool.Driver.Rules = kept
		}
	}
	return RefreshDescriptions(doc)
}

func ensureCWETaxon(run *SARIFRun, e cwe.Entry) {
	for i := range run.Taxonomies {
		t := &run.Taxonomies[i]
		if t.Name != "CWE" {
			continue
		}
		for _, taxon := range t.Taxa {
			if taxon.ID == e.ID {
				return
			}
		}
		t.Taxa = append(append([]SARIFTaxon(nil), t.Taxa...), SARIFTaxon{ID: e.ID, ShortDescription: SARIFMessage{Text: e.Name}})
		return
	}
	run.Taxonomies = append(run.Taxonomies, SARIFTaxonomy{Name: "CWE", Organization: "MITRE", ShortDescription: SARIFMessage{Text: "Common Weakness Enumeration"}, Taxa: []SARIFTaxon{{ID: e.ID, ShortDescription: SARIFMessage{Text: e.Name}}}})
}
