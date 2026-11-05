package auditctx

import (
	"regexp"

	"github.com/block/codecrucible/internal/auditcore"
)

const maxContextRequests = 8

var declarationName = regexp.MustCompile(`^[A-Za-z_$][\w$]*$`)

type RequestRecord struct {
	Request auditcore.ContextRequest `json:"request"`
	Status  string                   `json:"status"`
	Excerpt *Excerpt                 `json:"excerpt,omitempty"`
}

// ResolveRequests only consults the immutable admitted index. Exact-file symbol
// lookup avoids guessing an overload or following an external dependency.
func (ix *Index) ResolveRequests(requests []auditcore.ContextRequest) ([]Excerpt, []RequestRecord) {
	var excerpts []Excerpt
	var records []RequestRecord
	for i, q := range requests {
		if i == maxContextRequests {
			records = append(records, RequestRecord{Status: "request_limit"})
			break
		}
		r := RequestRecord{Request: q}
		lines := ix.source.Lines(q.File)
		e := Excerpt{File: q.File, Reason: "requested deciding evidence"}
		switch {
		case len(lines) == 0:
			r.Status = "outside_scope"
		case q.Symbol != "":
			if !declarationName.MatchString(q.Symbol) || q.Start != 0 || q.End != 0 {
				r.Status = "invalid_request"
				break
			}
			var defs []Def
			for _, d := range ix.source.Definitions(q.File) {
				if d.Name == q.Symbol {
					defs = append(defs, d)
				}
			}
			switch len(defs) {
			case 0:
				r.Status = "symbol_not_found"
			case 1:
				e = defExcerpt(defs[0], "requested declaration: "+q.Symbol)
			default:
				r.Status = "ambiguous_symbol"
			}
		case q.Start < 1 || q.Start > len(lines) || q.End < q.Start || q.End > len(lines) || q.End-q.Start >= 120:
			r.Status = "invalid_range"
		default:
			e.Start, e.End = q.Start, q.End
		}
		if r.Status == "" {
			r.Status, r.Excerpt = "resolved", &e
			excerpts = append(excerpts, e)
		}
		records = append(records, r)
	}
	return excerpts, records
}
