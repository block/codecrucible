package decision

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"sort"
	"strings"
)

// SourceRange and CoverageGap contain locations and categorical reasons only.
// A complete selection covers the selected claim context, not the repository.
type SourceRange struct {
	Path  string `json:"path"`
	Start int    `json:"start_line"`
	End   int    `json:"end_line"`
}
type CoverageGap struct {
	SourceRange
	Reason string `json:"reason"`
}
type EvidenceSelection struct {
	Evidence []Evidence    `json:"evidence"`
	Gaps     []CoverageGap `json:"gaps,omitempty"`
}

func (s EvidenceSelection) Complete() bool { return len(s.Evidence) > 0 && len(s.Gaps) == 0 }

type sourceUnit struct {
	SourceRange
	names, refs, calls map[string]bool
	function           bool
	header             bool
}
type indexedSource struct {
	units  []*sourceUnit
	parsed bool
}

// EvidenceIndex parses admitted sources once. Go declarations support focused
// selection; other languages and parse failures conservatively use full files.
// Symbol matching is best effort, never proof of reachability or mitigation.
type EvidenceIndex struct {
	files          map[string]string
	graph, reverse map[string][]string
	sources        map[string]indexedSource
}

func NewEvidenceIndex(files map[string]string, graph map[string][]string) *EvidenceIndex {
	index := &EvidenceIndex{files: files, graph: graph, reverse: map[string][]string{}, sources: map[string]indexedSource{}}
	for path, deps := range graph {
		for _, dep := range deps {
			index.reverse[dep] = append(index.reverse[dep], path)
		}
	}
	for path, content := range files {
		source := indexedSource{}
		if filepath.Ext(path) == ".go" {
			positions := token.NewFileSet()
			file, err := parser.ParseFile(positions, path, content, parser.ParseComments)
			if err == nil {
				source.parsed = true
				for _, decl := range file.Decls {
					unit := &sourceUnit{SourceRange: SourceRange{path, positions.Position(decl.Pos()).Line, positions.Position(decl.End()).Line}, names: map[string]bool{}, refs: map[string]bool{}, calls: map[string]bool{}}
					switch d := decl.(type) {
					case *ast.FuncDecl:
						unit.names[d.Name.Name] = true
						unit.function = true
						if d.Doc != nil {
							unit.Start = positions.Position(d.Doc.Pos()).Line
						}
					case *ast.GenDecl:
						unit.header = d.Tok == token.IMPORT
						if d.Doc != nil {
							unit.Start = positions.Position(d.Doc.Pos()).Line
						}
						for _, spec := range d.Specs {
							switch s := spec.(type) {
							case *ast.TypeSpec:
								unit.names[s.Name.Name] = true
							case *ast.ValueSpec:
								for _, name := range s.Names {
									unit.names[name.Name] = true
								}
							}
						}
					}
					ast.Inspect(decl, func(node ast.Node) bool {
						if id, ok := node.(*ast.Ident); ok {
							unit.refs[id.Name] = true
						}
						if call, ok := node.(*ast.CallExpr); ok {
							switch fun := call.Fun.(type) {
							case *ast.Ident:
								unit.calls[fun.Name] = true
							case *ast.SelectorExpr:
								unit.calls[fun.Sel.Name] = true
							}
						}
						return true
					})
					source.units = append(source.units, unit)
				}
			}
		}
		if !source.parsed {
			source.units = []*sourceUnit{{SourceRange: SourceRange{path, 1, len(strings.Split(strings.TrimSuffix(content, "\n"), "\n"))}}}
		}
		index.sources[path] = source
	}
	return index
}

// Select first reserves all cited scopes, then follows referenced local
// declarations and callers. Unrelated declarations and their imports cannot
// consume the context budget. Missing scopes/definitions remain explicit gaps.
func (index *EvidenceIndex) Select(cited []SourceRange, budget int) EvidenceSelection {
	out := EvidenceSelection{}
	queue := []*sourceUnit{}
	seen := map[*sourceUnit]bool{}
	gapSeen := map[CoverageGap]bool{}
	gap := func(span SourceRange, reason string) {
		g := CoverageGap{span, reason}
		if !gapSeen[g] {
			out.Gaps = append(out.Gaps, g)
			gapSeen[g] = true
		}
	}
	add := func(unit *sourceUnit) {
		if !seen[unit] {
			seen[unit] = true
			queue = append(queue, unit)
		}
	}
	for _, span := range cited {
		if span.End == 0 {
			span.End = span.Start
		}
		content, ok := index.files[span.Path]
		if !ok {
			gap(span, "missing_source")
			continue
		}
		if _, ok := SourceEvidence(span.Path, content, span.Start, span.End); !ok {
			gap(span, "invalid_location")
			continue
		}
		covered := false
		for _, unit := range index.sources[span.Path].units {
			if unit.Start <= span.Start && unit.End >= span.End {
				add(unit)
				covered = true
				break
			}
		}
		if !covered {
			// Package-level or multi-declaration spans require the full file.
			add(&sourceUnit{SourceRange: SourceRange{span.Path, 1, len(strings.Split(strings.TrimSuffix(content, "\n"), "\n"))}})
		}
	}
	if len(cited) == 0 {
		gap(SourceRange{}, "missing_location")
	}
	usedEvidence := map[string]bool{}
	budget -= 2 // JSON array delimiters; reserve one comma for each span below.
	for i := 0; i < len(queue); i++ {
		unit := queue[i]
		// Resolve an entire scope before admitting it. A partial function can hide
		// a dominating guard, so budget exhaustion cannot authorize a verdict.
		spans := []Evidence{}
		size := 0
		for start := unit.Start; start <= unit.End; start += 24 {
			evidence, _ := SourceEvidence(unit.Path, index.files[unit.Path], start, min(start+23, unit.End))
			if usedEvidence[evidence.ID] {
				continue
			}
			encoded, _ := json.Marshal(evidence)
			size += len(encoded) + 1
			if size > budget {
				break
			}
			spans = append(spans, evidence)
		}
		if size > budget {
			gap(unit.SourceRange, "evidence_budget")
			continue
		}
		budget -= size
		for _, e := range spans {
			usedEvidence[e.ID] = true
			out.Evidence = append(out.Evidence, e)
		}
		source := index.sources[unit.Path]
		if unit.header {
			continue
		}
		for _, header := range source.units {
			if header.header {
				add(header)
			}
		}
		paths := append([]string{unit.Path}, index.graph[unit.Path]...)
		sort.Strings(paths)
		for _, path := range paths {
			dependency, ok := index.sources[path]
			if !ok {
				gap(SourceRange{Path: path}, "missing_source")
				continue
			}
			for _, candidate := range dependency.units {
				if !source.parsed || !dependency.parsed || intersects(unit.refs, candidate.names) {
					add(candidate)
				}
			}
		}
		if unit.function {
			callers := append([]string{unit.Path}, index.reverse[unit.Path]...)
			sort.Strings(callers)
			for _, path := range callers {
				for _, caller := range index.sources[path].units {
					if intersects(unit.names, caller.calls) {
						add(caller)
					}
				}
			}
		}
	}
	return out
}
func intersects(left, right map[string]bool) bool {
	for name := range left {
		if right[name] {
			return true
		}
	}
	return false
}
