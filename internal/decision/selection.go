package decision

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"sort"
	"strings"
	"sync"
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
	names, refs map[string]bool
	controls    map[string]bool
	function    bool
	header      bool
	codeStart   int
	// Non-Go structure: enclosing type or namespace, a type header,
	// router/app middleware registrations that guard later handlers, and
	// decorated definitions, which register themselves (@app.route).
	parent    *sourceUnit
	container bool
	guard     bool
	annotated bool
}
type indexedSource struct {
	units  []*sourceUnit
	parsed bool
}

// EvidenceIndex parses admitted sources once. Go declarations and the
// statements of other structural languages support focused selection; other
// languages and parse failures conservatively use full files.
// Symbol matching is best effort, never proof of reachability or mitigation.
type EvidenceIndex struct {
	files          map[string]string
	graph, reverse map[string][]string
	sources        map[string]indexedSource
	packagesOnce   sync.Once
	packages       map[string][]string
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
					unit := &sourceUnit{SourceRange: SourceRange{path, positions.Position(decl.Pos()).Line, positions.Position(decl.End()).Line}, names: map[string]bool{}, refs: map[string]bool{}}
					unit.codeStart = unit.Start
					unit.controls = map[string]bool{}
					controlRefs := func(node ast.Node) {
						ast.Inspect(node, func(n ast.Node) bool {
							if id, ok := n.(*ast.Ident); ok {
								unit.controls[id.Name] = true
							}
							return true
						})
					}
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
						if conditional, ok := node.(*ast.IfStmt); ok {
							controlRefs(conditional.Cond)
						}
						if id, ok := node.(*ast.Ident); ok {
							unit.refs[id.Name] = true
						}
						if call, ok := node.(*ast.CallExpr); ok {
							name := ""
							switch fun := call.Fun.(type) {
							case *ast.Ident:
								name = fun.Name
							case *ast.SelectorExpr:
								name = fun.Sel.Name
							}
							// Conventional middleware registration is extra context,
							// never proof that a guard applies to a particular route.
							if name == "Use" || name == "With" {
								for _, arg := range call.Args {
									controlRefs(arg)
								}
							}
						}
						return true
					})
					source.units = append(source.units, unit)
				}
			}
		} else if units, ok := structuralUnits(path, content); ok {
			source.parsed = true
			source.units = units
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
	return index.selectEvidence(cited, budget, nil)
}

// suppliedFiles enables optional selection: follow source relations through
// already supplied files without charging their scopes to this budget. Return
// other declarations as indivisible candidates, omitting import headers.
func (index *EvidenceIndex) selectEvidence(cited []SourceRange, budget int, suppliedFiles map[string]bool) EvidenceSelection {
	optionalOnly := suppliedFiles != nil
	out := EvidenceSelection{}
	queue := []*sourceUnit{}
	seen := map[*sourceUnit]bool{}
	followCallers := map[*sourceUnit]bool{}
	callerContext := map[*sourceUnit]bool{}
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
	// Middleware registrations contribute the guards they install, not every
	// handler their router references.
	addGuard := func(unit *sourceUnit) {
		if !seen[unit] {
			callerContext[unit] = true
		}
		add(unit)
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
				followCallers[unit] = true
				add(unit)
				covered = true
				break
			}
		}
		if !covered {
			// Package-level or multi-declaration spans require the full file.
			unit := &sourceUnit{SourceRange: SourceRange{span.Path, 1, len(strings.Split(strings.TrimSuffix(content, "\n"), "\n"))}}
			followCallers[unit] = true
			add(unit)
		}
	}
	if len(cited) == 0 {
		gap(SourceRange{}, "missing_location")
	}
	usedEvidence := map[string]bool{}
	budget -= 2 // JSON array delimiters; reserve one comma for each span below.
	for i := 0; i < len(queue); i++ {
		unit := queue[i]
		if optionalOnly && unit.header {
			continue
		}
		// Resolve an entire scope before admitting it. A partial function can hide
		// a dominating guard, so budget exhaustion cannot authorize a verdict.
		spans := []Evidence{}
		size := 0
		step := 24
		if optionalOnly {
			step = unit.End - unit.Start + 1
		}
		for start := unit.Start; start <= unit.End && !suppliedFiles[unit.Path]; start += step {
			evidence, _ := SourceEvidence(unit.Path, index.files[unit.Path], start, min(start+step-1, unit.End))
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
		// Members need their type declaration: annotations, base types, and
		// class-level decorators can decide whether a method is reachable.
		for parent := unit.parent; parent != nil; parent = parent.parent {
			add(parent)
		}
		// Guards apply to registrations after them. A plain named definition
		// is guarded through its registration, reached below as a caller.
		if followCallers[unit] && (callerContext[unit] || unit.annotated || len(unit.names) == 0) {
			for _, guard := range source.units {
				if guard.guard && guard.parent == unit.parent && guard.Start < unit.Start {
					addGuard(guard)
				}
			}
			if unit.parent == nil {
				importers := append([]string{}, index.reverse[unit.Path]...)
				sort.Strings(importers)
				for _, path := range importers {
					for _, guard := range index.sources[path].units {
						if guard.guard && guard.parent == nil {
							addGuard(guard)
						}
					}
				}
			}
		}
		// Ancestor scopes preserve registration and guard ordering. Following all
		// their outgoing handlers would turn one route into the whole application.
		{
			paths := append([]string{unit.Path}, index.graph[unit.Path]...)
			sort.Strings(paths)
			for _, path := range paths {
				dependency, ok := index.sources[path]
				if !ok {
					gap(SourceRange{Path: path}, "missing_source")
					continue
				}
				for _, candidate := range dependency.units {
					references := unit.refs
					if callerContext[unit] {
						references = unit.controls
					}
					if !source.parsed || !dependency.parsed || intersects(references, candidate.names) {
						add(candidate)
					}
				}
			}
		}
		if unit.function && followCallers[unit] {
			callers := append([]string{unit.Path}, index.reverse[unit.Path]...)
			sort.Strings(callers)
			for _, path := range callers {
				for _, caller := range index.sources[path].units {
					// Function values passed to routers/middleware are incoming uses
					// even though the callback itself is not the CallExpr target.
					if caller != unit && caller.function && intersects(unit.names, caller.refs) {
						if seen[caller] && !followCallers[caller] {
							queue = append(queue, caller)
						}
						followCallers[caller] = true
						if !seen[caller] {
							callerContext[caller] = true
						}
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

// RelevantEvidence selects complete declarations using shared identifiers, not
// the file header. Missing or oversized scopes cannot authorize a grouping hint.
func (index *EvidenceIndex) RelevantEvidence(path string, terms map[string]bool, budget int) []Evidence {
	type candidate struct {
		unit  *sourceUnit
		score int
	}
	candidates := []candidate{}
	for _, unit := range index.sources[path].units {
		if unit.header {
			continue
		}
		score := 0
		for name := range terms {
			if unit.refs[name] {
				score++
			}
			if unit.names[name] {
				score += 2
			}
		}
		if score > 0 || !index.sources[path].parsed {
			candidates = append(candidates, candidate{unit, score})
		}
	}
	sort.SliceStable(candidates, func(i, j int) bool { return candidates[i].score > candidates[j].score })
	out := []Evidence{}
	for _, candidate := range candidates {
		u := candidate.unit
		e, ok := SourceEvidence(path, index.files[path], max(u.Start, u.codeStart), u.End)
		if !ok {
			continue
		}
		encoded, _ := json.Marshal(e)
		if len(encoded)+1 > budget {
			continue
		}
		budget -= len(encoded) + 1
		out = append(out, e)
		if len(out) == 3 {
			break
		}
	}
	return out
}
