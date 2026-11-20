package auditctx

import (
	"regexp"
	"strconv"

	"github.com/block/codecrucible/internal/auditcore"
)

const (
	// maxContextRequests bounds one retrieval round. Later requests are
	// recorded as request_limit rather than silently dropped.
	maxContextRequests = 8
	// maxRequestLines is the longest range or declaration a request returns. It
	// matches the longest range a quote may cite, so everything sent can be cited.
	maxRequestLines = 120
	// maxEchoed bounds how much model-chosen text is echoed back in a record.
	maxEchoed = 256
)

var declarationName = regexp.MustCompile(`^[A-Za-z_$][\w$]*$`)

// Request statuses. ResolveRequests only reports resolved or a failure; Bundle
// turns resolved into included or budget_exhausted once it has applied the
// token budget, using the same reason strings as its omission records.
const (
	RequestResolved        = "resolved"
	RequestIncluded        = "included"
	RequestBudgetExhausted = "budget_exhausted"
	RequestOutsideScope    = "outside_scope"
	RequestAmbiguousSymbol = "ambiguous_symbol"
	RequestSymbolNotFound  = "symbol_not_found"
	RequestInvalid         = "invalid_request"
	RequestInvalidRange    = "invalid_range"
	RequestLimit           = "request_limit"
)

// RequestRecord is the outcome of one named context request.
type RequestRecord struct {
	Request auditcore.ContextRequest `json:"request"`
	Status  string                   `json:"status"`
	Excerpt *Excerpt                 `json:"excerpt,omitempty"`
}

// ResolveRequests answers a bounded round of named-symbol and line-range
// requests from the shared source snapshot. It reads only admitted files by
// exact path, never guesses between overloads or follows an external
// dependency, and returns one record per request. It does not apply a token
// budget: Bundle admits the returned excerpts and records the ones it cannot.
func (ix *Index) ResolveRequests(requests []auditcore.ContextRequest) ([]Excerpt, []RequestRecord) {
	var excerpts []Excerpt
	var records []RequestRecord
	for i, q := range requests {
		if i == maxContextRequests {
			records = append(records, RequestRecord{Status: RequestLimit})
			break
		}
		r := RequestRecord{Request: q}
		if len(q.File) > maxEchoed {
			r.Request.File = q.File[:maxEchoed]
		}
		if len(q.Symbol) > maxEchoed {
			r.Request.Symbol = q.Symbol[:maxEchoed]
		}
		lines := ix.source.Lines(q.File)
		e := Excerpt{File: q.File, Reason: "requested deciding evidence"}
		switch {
		case len(lines) == 0:
			r.Status = RequestOutsideScope
		case q.Symbol != "":
			if !declarationName.MatchString(q.Symbol) || q.Start != 0 || q.End != 0 {
				r.Status = RequestInvalid
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
				r.Status = RequestSymbolNotFound
			case 1:
				d := defs[0]
				e = Excerpt{File: d.File, Start: d.Line, End: min(d.End, d.Line+maxRequestLines-1), Reason: "requested declaration: " + q.Symbol}
				if e.End < d.End {
					// Say so, so a cut-off body is not read as the whole body.
					e.Reason += " (truncated at " + strconv.Itoa(maxRequestLines) + " lines)"
				}
			default:
				r.Status = RequestAmbiguousSymbol
			}
		case q.Start < 1 || q.Start > len(lines) || q.End < q.Start || q.End > len(lines) || q.End-q.Start >= maxRequestLines:
			r.Status = RequestInvalidRange
		default:
			e.Start, e.End = q.Start, q.End
		}
		if r.Status == "" {
			r.Status, r.Excerpt = RequestResolved, &e
			excerpts = append(excerpts, e)
		}
		records = append(records, r)
	}
	return excerpts, records
}
