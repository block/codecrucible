package sarif

import (
	"log/slog"
	"path"
	"strings"
)

// ResolvePath maps a model-reported file path onto a scanned file. Models
// sometimes drop a leading directory ("routes/a.js" for "app/routes/a.js") or
// add "./". A path is repaired only when exactly one scanned file ends with it
// at a path-segment boundary, so an ambiguous path is never guessed; absolute
// and parent-relative paths are never repaired. ok reports whether the
// returned path names a scanned file.
func ResolvePath(files FileMap, reported string) (resolved string, ok bool) {
	if _, ok := files[reported]; ok {
		return reported, true
	}
	clean := path.Clean(strings.TrimSpace(reported))
	if clean == "." || clean == "" || path.IsAbs(clean) || strings.HasPrefix(clean, "../") {
		return reported, false
	}
	if _, ok := files[clean]; ok {
		return clean, true
	}
	match := ""
	for p := range files {
		if strings.HasSuffix(p, "/"+clean) {
			if match != "" {
				return reported, false
			}
			match = p
		}
	}
	if match == "" {
		return reported, false
	}
	return match, true
}

// ResolveLocations repairs result and code-flow URIs in a saved document with
// ResolvePath, records the reported path, and restores primary snippets that
// could not be extracted from the unrepaired path. Build applies the same
// repair to new findings.
func ResolveLocations(doc SARIFDocument, files FileMap) SARIFDocument {
	doc.Runs = append([]SARIFRun(nil), doc.Runs...)
	for i := range doc.Runs {
		run := &doc.Runs[i]
		run.Results = append([]SARIFResult(nil), run.Results...)
		for j := range run.Results {
			r := &run.Results[j]
			if len(r.Locations) > 0 {
				r.Locations = append([]SARIFLocation(nil), r.Locations...)
				loc := &r.Locations[0].PhysicalLocation
				uri := loc.ArtifactLocation.URI
				if resolved, ok := ResolvePath(files, uri); ok && resolved != uri {
					loc.ArtifactLocation.URI = resolved
					props := FindingProperties{}
					if r.Properties != nil {
						props = *r.Properties
					}
					if props.ReportedPath == "" {
						props.ReportedPath = uri
					}
					r.Properties = &props
					if reg := loc.Region; reg != nil && reg.Snippet == nil && reg.StartLine > 0 {
						region := *reg
						if snippet := extractSnippet(files, resolved, reg.StartLine, reg.EndLine, slog.Default()); snippet != "" {
							region.Snippet = &SARIFSnippet{Text: snippet}
						}
						loc.Region = &region
					}
				}
			}
			r.CodeFlows = resolveCodeFlows(r.CodeFlows, files)
		}
	}
	return doc
}

func resolveCodeFlows(flows []SARIFCodeFlow, files FileMap) []SARIFCodeFlow {
	if len(flows) == 0 {
		return flows
	}
	out := make([]SARIFCodeFlow, len(flows))
	for i, flow := range flows {
		out[i].ThreadFlows = make([]SARIFThreadFlow, len(flow.ThreadFlows))
		for j, thread := range flow.ThreadFlows {
			locations := append([]SARIFThreadFlowLocation(nil), thread.Locations...)
			for k := range locations {
				uri := &locations[k].Location.PhysicalLocation.ArtifactLocation.URI
				if resolved, ok := ResolvePath(files, *uri); ok {
					*uri = resolved
				}
			}
			out[i].ThreadFlows[j].Locations = locations
		}
	}
	return out
}
