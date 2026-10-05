// Package cwe provides the pinned, offline CWE vocabulary used for classification.
package cwe

import (
	_ "embed"
	"encoding/json"
	"math"
	"regexp"
	"sort"
	"strings"
)

//go:embed catalog.json
var catalogJSON []byte

type Entry struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	Description  string   `json:"description"`
	Abstraction  string   `json:"abstraction"`
	Status       string   `json:"status"`
	Mapping      string   `json:"mapping"`
	MappingNotes string   `json:"mapping_notes"`
	Parents      []string `json:"parents"`
}

func (e Entry) Mappable() bool {
	return e.Status != "Deprecated" && (e.Mapping == "Allowed" || e.Mapping == "Allowed-with-Review")
}

var catalog struct {
	Version string  `json:"version"`
	Notice  string  `json:"notice"`
	Entries []Entry `json:"entries"`
}
var byID = map[string]Entry{}
var words = regexp.MustCompile(`[a-z][a-z0-9]+`)
var idPattern = regexp.MustCompile(`(?i)^CWE-([1-9][0-9]*)(?:\s*:\s*[^\r\n]+)?$`)
var stop = map[string]bool{}
var termCounts = map[string]int{}
var searchTerms = map[string]map[string]float64{}

func init() {
	if err := json.Unmarshal(catalogJSON, &catalog); err != nil {
		panic(err)
	}
	for _, s := range strings.Fields("the and that this with from into when without which such could would should does not are for has have its can may use uses using product software application attacker vulnerability finding code source input output value data control security improper CWE") {
		stop[strings.ToLower(s)] = true
	}
	for _, e := range catalog.Entries {
		byID[e.ID] = e
		terms := map[string]float64{}
		for _, t := range tokens(e.Description) {
			terms[t] = 1
		}
		for _, t := range tokens(e.Name) {
			terms[t] = 4
		}
		searchTerms[e.ID] = terms
		for t := range terms {
			termCounts[t]++
		}
	}
}

func Version() string { return catalog.Version }
func Notice() string  { return catalog.Notice }

// Lookup accepts an exact ID, optionally followed by its display title. It never
// extracts an arbitrary ID from prose or accepts an unknown catalog entry.
func Lookup(value string) (Entry, bool) {
	m := idPattern.FindStringSubmatch(strings.TrimSpace(value))
	if len(m) == 0 {
		return Entry{}, false
	}
	e, ok := byID["CWE-"+m[1]]
	return e, ok
}

func tokens(s string) []string {
	var out []string
	for _, t := range words.FindAllString(strings.ToLower(s), -1) {
		if !stop[t] {
			out = append(out, t)
		}
	}
	return out
}

// Candidates ranks independently retrieved definitions and includes the original
// mappable assignment. This is a bounded shortlist, never an exhaustive taxonomy.
func Candidates(text, original string, limit int) []Entry {
	if limit <= 0 {
		return nil
	}
	query := map[string]bool{}
	for _, t := range tokens(text) {
		query[t] = true
	}
	queryTerms := make([]string, 0, len(query))
	for term := range query {
		queryTerms = append(queryTerms, term)
	}
	sort.Strings(queryTerms)
	type hit struct {
		e     Entry
		score float64
	}
	var hits []hit
	prior, _ := Lookup(original)
	for _, e := range catalog.Entries {
		if !e.Mappable() {
			continue
		}
		score := 0.0
		for _, t := range queryTerms {
			if weight := searchTerms[e.ID][t]; weight > 0 {
				score += weight * math.Log(1+float64(len(catalog.Entries))/float64(termCounts[t]))
			}
		}
		if score > 0 || e.ID == prior.ID {
			hits = append(hits, hit{e, score})
		}
	}
	sort.Slice(hits, func(i, j int) bool {
		if hits[i].score != hits[j].score {
			return hits[i].score > hits[j].score
		}
		return hits[i].e.ID < hits[j].e.ID
	})
	var out []Entry
	if prior.Mappable() {
		out = append(out, prior)
	}
	for _, h := range hits {
		if len(out) >= limit {
			break
		}
		if h.e.ID != prior.ID {
			out = append(out, h.e)
		}
	}
	return out
}
