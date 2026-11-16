// Package sourceindex extracts reusable, best-effort facts from admitted
// repository files. It never builds the project or reads outside that snapshot.
// Syntax facts are context hints, not proof of data flow or a security control.
package sourceindex

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"
)

const Version = "1"

// Def identifies a declaration. Binding details remain private to the extractor.
type Def struct {
	Name               string
	Type               bool
	File               string
	Line, End          int
	owner              string
	params             []parameter
	bodyStart, bodyEnd int
}

// DefID is stable within a source snapshot and can be used as a map key.
type DefID = defID

func (d Def) ID() DefID { return d.id() }

// Reference is a possible name use. Offsets and lines refer to original source.
type Reference struct {
	Name, Qualifier string
	Offset, Line    int
}

func (r Reference) internal() reference { return reference{r.Name, r.Qualifier, r.Offset} }
func publicReference(r reference, line int) Reference {
	return Reference{r.name, r.qualifier, r.offset, line}
}

type BoundCall struct {
	Reference
	binding boundCall
}
type ForwardedUse struct {
	Reference
	Parameter string
}

// Snapshot identifies the admitted bytes separately from the extraction version.
// Counts describe extraction capability; lexical fallback never drops a file.
type Snapshot struct {
	Version           string         `json:"version"`
	SourceFingerprint string         `json:"sourceFingerprint"`
	IndexFingerprint  string         `json:"indexFingerprint"`
	Files             int            `json:"files"`
	Lines             int            `json:"lines"`
	Extraction        map[string]int `json:"extraction"`
	Imports           map[string]int `json:"imports"`
}

type Index struct {
	files     map[string]string
	paths     []string
	lines     map[string][]string
	defs      map[string][]Def
	byFile    map[string][]Def
	sources   map[string]*sourceInfo
	imports   []Import
	graph     map[string][]string
	summaries map[string]string
	snapshot  Snapshot
}

// New builds one immutable snapshot from already-filtered, repo-relative files.
func New(files map[string]string) *Index {
	ix := &Index{files: make(map[string]string, len(files)), lines: map[string][]string{},
		defs: map[string][]Def{}, byFile: map[string][]Def{}, sources: map[string]*sourceInfo{},
		graph: map[string][]string{}, summaries: map[string]string{}}
	for p, text := range files {
		ix.files[p] = text
		ix.paths = append(ix.paths, p)
	}
	sort.Strings(ix.paths)
	ix.snapshot = Snapshot{Version: Version, Files: len(files), Extraction: map[string]int{}, Imports: map[string]int{}}
	type identity struct{ Path, SHA256 string }
	identities := make([]identity, 0, len(files))
	for _, p := range ix.paths {
		text := ix.files[p]
		lines := strings.Split(text, "\n")
		ix.lines[p] = lines
		ix.snapshot.Lines += len(lines)
		src := adapterFor(p).parse(p, text)
		ix.sources[p] = src
		ix.snapshot.Extraction[src.mode]++
		for _, d := range src.defs {
			ix.defs[d.Name] = append(ix.defs[d.Name], d)
		}
		ix.byFile[p] = src.defs
		if summary := summarizeSource(p, text, src); summary != "" {
			ix.summaries[p] = summary
		}
		identities = append(identities, identity{p, Fingerprint(text)})
	}
	data, _ := json.Marshal(identities)
	ix.snapshot.SourceFingerprint = Fingerprint(string(data))
	ix.buildImports()
	data, _ = json.Marshal(struct {
		Version, Source string
		Imports         []Import
	}{Version, ix.snapshot.SourceFingerprint, ix.imports})
	ix.snapshot.IndexFingerprint = Fingerprint(string(data))
	return ix
}

func Fingerprint(text string) string {
	sum := sha256.Sum256([]byte(text))
	return "sha256:" + hex.EncodeToString(sum[:])
}
func (ix *Index) Snapshot() Snapshot {
	snapshot := ix.snapshot
	snapshot.Extraction = cloneCounts(snapshot.Extraction)
	snapshot.Imports = cloneCounts(snapshot.Imports)
	return snapshot
}
func cloneCounts(in map[string]int) map[string]int {
	out := make(map[string]int, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
func (ix *Index) Paths() []string                    { return append([]string(nil), ix.paths...) }
func (ix *Index) Content(file string) (string, bool) { s, ok := ix.files[file]; return s, ok }

// Lines and Code return read-only views of original and extractor-visible lines.
func (ix *Index) Lines(file string) []string { return ix.lines[file] }
func (ix *Index) Code(file string) []string {
	if s := ix.sources[file]; s != nil {
		return s.code
	}
	return nil
}
func (ix *Index) Language(file string) string {
	if s := ix.sources[file]; s != nil {
		return s.language
	}
	return ""
}
func (ix *Index) Mode(file string) string {
	if s := ix.sources[file]; s != nil {
		return s.mode
	}
	return ""
}
func (ix *Index) Definitions(file string) []Def    { return append([]Def(nil), ix.byFile[file]...) }
func (ix *Index) ImportGraph() map[string][]string { return cloneLists(ix.graph) }
func (ix *Index) Imports() []Import {
	out := append([]Import(nil), ix.imports...)
	for i := range out {
		out[i].Targets = append([]string(nil), out[i].Targets...)
	}
	return out
}
func (ix *Index) ExportSummaries() map[string]string {
	out := make(map[string]string, len(ix.summaries))
	for k, v := range ix.summaries {
		out[k] = v
	}
	return out
}
func cloneLists(in map[string][]string) map[string][]string {
	out := make(map[string][]string, len(in))
	for k, v := range in {
		out[k] = append([]string(nil), v...)
	}
	return out
}
func (ix *Index) Enclosing(file string, line int) (Def, bool) {
	var best Def
	found := false
	for _, d := range ix.byFile[file] {
		if d.Line > line {
			break
		}
		if !d.Type && line <= d.End {
			best, found = d, true
		}
	}
	return best, found
}
func (ix *Index) Resolve(file string, ref Reference, typ bool) (Def, bool) {
	if ix.sources[file] == nil {
		return Def{}, false
	}
	return ix.resolve(file, ref.internal(), typ)
}
func (ix *Index) IsDefinition(file string, line int, name string) bool {
	return ix.isDefinition(file, line, name)
}
func (ix *Index) Calls(file string, lo, hi int) []Reference {
	var out []Reference
	if src := ix.sources[file]; src != nil {
		for _, c := range src.calls {
			if c.line >= lo && c.line <= hi {
				out = append(out, publicReference(c.reference, c.line))
			}
		}
	}
	return out
}
func (ix *Index) ContainingCalls(file string, start, end, lo int) []BoundCall {
	var out []BoundCall
	if src := ix.sources[file]; src != nil {
		for _, c := range src.containingCalls(start, end, lo) {
			out = append(out, BoundCall{publicReference(c.reference, c.line), c})
		}
	}
	return out
}
func (ix *Index) TypeReferences(file string, lo, hi int) []Reference {
	var out []Reference
	offset := 0
	for i, line := range ix.Code(file) {
		if i+1 >= lo && i+1 <= hi {
			for _, m := range typeName.FindAllStringSubmatchIndex(line, -1) {
				r := Reference{Name: line[m[4]:m[5]], Offset: offset + m[0], Line: i + 1}
				if m[2] >= 0 {
					r.Qualifier = line[m[2]:m[3]]
					out = append(out, Reference{Name: r.Qualifier, Offset: r.Offset, Line: r.Line})
				}
				out = append(out, r)
			}
		}
		offset += len(line) + 1
	}
	return out
}

// ForwardedUses returns one-hop, explicit parameter uses. Ranking, hop limits,
// ambiguous resolution, and evidence budgets belong to the caller.
func (ix *Index) ForwardedUses(d Def, c BoundCall) []ForwardedUse {
	param := d.boundParameter(c.binding)
	if param == "" || d.bodyEnd <= d.bodyStart {
		return nil
	}
	var out []ForwardedUse
	for _, next := range ix.sources[d.File].calls {
		if next.start < d.bodyStart || next.end > d.bodyEnd {
			continue
		}
		nested := false
		for _, span := range ix.sources[d.File].unbound {
			if span[0] >= d.bodyStart && span[1] <= d.bodyEnd && next.start >= span[0] && next.end <= span[1] {
				nested = true
				break
			}
		}
		for _, child := range ix.byFile[d.File] {
			if child.id() != d.id() && child.bodyStart >= d.bodyStart && child.bodyEnd <= d.bodyEnd && next.start >= child.bodyStart && next.end <= child.bodyEnd {
				nested = true
				break
			}
		}
		if nested {
			continue
		}
		for _, a := range next.args {
			if a.direct == param {
				out = append(out, ForwardedUse{publicReference(next.reference, next.line), param})
				break
			}
		}
	}
	return out
}
