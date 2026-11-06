package sarif

import "strings"

// ValidateSourceLocations clamps invalid ends when the source supports the start.
// Invalid starts are removed; original locations remain as diagnostic data.
func ValidateSourceLocations(doc SARIFDocument, files FileMap) SARIFDocument {
	doc.Runs = append([]SARIFRun{}, doc.Runs...)
	for ri := range doc.Runs {
		run := &doc.Runs[ri]
		run.Results = append([]SARIFResult{}, run.Results...)
		for i := range run.Results {
			r := &run.Results[i]
			r.Locations = append([]SARIFLocation{}, r.Locations...)
			for j := range r.Locations {
				loc := &r.Locations[j].PhysicalLocation
				reg := loc.Region
				if reg == nil {
					continue
				}
				bad := reg.StartLine < 1 || (reg.EndLine != 0 && reg.EndLine < reg.StartLine)
				var repaired *SARIFRegion
				if reg.StartLine >= 1 && reg.EndLine != 0 && reg.EndLine < reg.StartLine {
					clamped := *reg
					clamped.EndLine = reg.StartLine
					repaired = &clamped
				}
				if content, ok := files[loc.ArtifactLocation.URI]; ok {
					n := len(strings.Split(strings.TrimSuffix(content, "\n"), "\n"))
					bad = bad || reg.StartLine > n || reg.EndLine > n
					if reg.StartLine > n {
						repaired = nil
					}
					if bad && reg.StartLine >= 1 && reg.StartLine <= n {
						clamped := *reg
						clamped.EndLine = max(reg.StartLine, min(reg.EndLine, n))
						repaired = &clamped
					}
				}
				if !bad {
					continue
				}
				p := FindingProperties{}
				if r.Properties != nil {
					p = *r.Properties
				}
				p.ReportedLocations = append(append([]SARIFLocation{}, p.ReportedLocations...), r.Locations[j])
				reason := "invalid_source_region"
				if repaired != nil {
					reason = "clamped_source_region"
				}
				p.LocationWarnings = append(append([]string{}, p.LocationWarnings...), reason)
				r.Properties = &p
				loc.Region = repaired
			}
		}
	}
	return doc
}
