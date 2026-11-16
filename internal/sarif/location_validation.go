package sarif

import "strings"

// ValidateSourceLocations removes invalid primary regions without guessing a
// different source anchor. The original location is retained as diagnostic data.
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
				if content, ok := files[loc.ArtifactLocation.URI]; ok {
					n := len(strings.Split(strings.TrimSuffix(content, "\n"), "\n"))
					bad = bad || reg.StartLine > n || reg.EndLine > n
				}
				if !bad {
					continue
				}
				p := FindingProperties{}
				if r.Properties != nil {
					p = *r.Properties
				}
				p.ReportedLocations = append(append([]SARIFLocation{}, p.ReportedLocations...), r.Locations[j])
				p.LocationWarnings = append(append([]string{}, p.LocationWarnings...), "invalid_source_region")
				r.Properties = &p
				loc.Region = nil
			}
		}
	}
	return doc
}
