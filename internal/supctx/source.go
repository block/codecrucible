// Package supctx loads supplementary context (docs, API specs, sibling repos,
// internal notes) and packs it into a token-budget-safe block for injection
// into analysis and audit prompts.
//
// The package is deliberately decoupled from the prompt assembler: it produces
// a rendered string plus accounting metadata, and the caller decides where in
// the prompt that string lands.
package supctx

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/block/codecrucible/internal/ingest"
)

// Source describes one piece of supplementary context as configured by the
// user. The four types share a single struct so config unmarshal stays flat.
type Source struct {
	// Name labels the source in the rendered prompt block and in logs.
	Name string `mapstructure:"name"`

	// Type is one of "path", "repo", "url", "inline".
	Type string `mapstructure:"type"`

	// Location is interpreted per-type: filesystem path, git clone URL,
	// HTTP(S) URL, or the literal content for inline.
	Location string `mapstructure:"location"`

	// Priority orders packing when the combined sources exceed the budget.
	// Higher wins; ties broken by declaration order.
	Priority int `mapstructure:"priority"`

	// Compress marks the source as eligible for LLM pre-compression when it
	// alone would exceed its fair share of the budget.
	Compress bool `mapstructure:"compress"`

	// Phases limits which scan phases receive this source. Empty means all
	// LLM phases (currently "analysis" and "audit" — feature-detection is
	// never fed supplementary context).
	Phases []string `mapstructure:"phases"`

	// Include/Exclude are glob filters for "path" and "repo" types, reusing
	// the ingest package's FilterConfig semantics.
	Include []string `mapstructure:"include"`
	Exclude []string `mapstructure:"exclude"`
}

// Loaded is a source whose content has been fetched and token-counted but not
// yet packed. Priority is carried through so Pack can sort.
type Loaded struct {
	Name     string
	Content  string
	Tokens   int
	Priority int
	Compress bool
	Phases   []string
}

// TokenCounter is the subset of chunk.TokenCounter this package needs.
// Defined locally to avoid an import cycle if chunk ever wants supctx.
type TokenCounter interface {
	Count(text string) int
}

// fetchTimeout bounds git clone and HTTP fetch. Failures skip the source
// rather than aborting the scan.
const fetchTimeout = 60 * time.Second

// LoadAll fetches every source concurrently-ish (sequential for now — the
// dominant cost is the LLM calls downstream, not loading a few files) and
// returns them token-counted. Load errors are logged and the source dropped;
// the scan proceeds with whatever loaded successfully.
func LoadAll(ctx context.Context, srcs []Source, counter TokenCounter) []Loaded {
	var out []Loaded
	for i, s := range srcs {
		if s.Name == "" {
			s.Name = fmt.Sprintf("context-%d", i+1)
		}
		content, err := loadOne(ctx, s)
		if err != nil {
			slog.Warn("skipping context source", "name", s.Name, "type", s.Type, "error", err)
			continue
		}
		if strings.TrimSpace(content) == "" {
			slog.Warn("context source is empty, skipping", "name", s.Name)
			continue
		}
		out = append(out, Loaded{
			Name:     s.Name,
			Content:  content,
			Tokens:   counter.Count(content),
			Priority: s.Priority,
			Compress: s.Compress,
			Phases:   s.Phases,
		})
	}
	return out
}

func loadOne(ctx context.Context, s Source) (string, error) {
	switch strings.ToLower(s.Type) {
	case "inline":
		return s.Location, nil
	case "path":
		return loadPath(s.Location, s.Include, s.Exclude)
	case "repo":
		return loadRepo(ctx, s.Location, s.Include, s.Exclude)
	case "url":
		return loadURL(ctx, s.Location)
	default:
		return "", fmt.Errorf("unknown context source type %q", s.Type)
	}
}

// loadPath handles both single files and directories. Directories go through
// the ingest walker/filter so .gitignore, binary-skip, and glob filters all
// apply exactly as they do for the scan target.
func loadPath(location string, include, exclude []string) (string, error) {
	info, err := os.Stat(location)
	if err != nil {
		return "", err
	}
	if !info.IsDir() {
		data, err := os.ReadFile(location)
		if err != nil {
			return "", err
		}
		return renderFiles([]ingest.SourceFile{{
			Path:    filepath.Base(location),
			Content: string(data),
		}}), nil
	}

	files, err := ingest.WalkDir(location)
	if err != nil {
		return "", err
	}
	filtered, _ := ingest.FilterFiles(files, ingest.FilterConfig{
		IncludeTests: true, // user explicitly pointed at this dir — don't second-guess
		IncludeDocs:  true,
		Include:      include,
		Exclude:      exclude,
	})
	return renderFiles(filtered), nil
}

// loadRepo shallow-clones into a temp dir, delegates to loadPath, then cleans
// up. The temp dir lives for the lifetime of the process (not just this call)
// because the returned string references no files — content is already read.
func loadRepo(ctx context.Context, gitURL string, include, exclude []string) (string, error) {
	tmp, err := os.MkdirTemp("", "ri-ctx-*")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(tmp)

	cctx, cancel := context.WithTimeout(ctx, fetchTimeout)
	defer cancel()

	cmd := exec.CommandContext(cctx, "git", "clone", "--depth", "1", "--quiet", gitURL, tmp)
	cmd.Stderr = nil
	if out, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("git clone: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return loadPath(tmp, include, exclude)
}

// allowPrivateHosts disables the SSRF check on initial URLs. Set to true in
// tests that use httptest.Server (which binds to 127.0.0.1).
var allowPrivateHosts = false

// loadURL fetches over HTTP(S), refusing other schemes and requests/redirects
// to private IP ranges. HTML responses get a crude tag-strip so the prompt
// isn't half angle brackets.
func loadURL(ctx context.Context, rawURL string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", fmt.Errorf("unsupported URL scheme %q", u.Scheme)
	}
	if !allowPrivateHosts && isPrivateHost(u.Hostname()) {
		return "", fmt.Errorf("request to private address %s refused", u.Host)
	}

	client := &http.Client{
		Timeout: fetchTimeout,
		CheckRedirect: func(req *http.Request, _ []*http.Request) error {
			// Always check redirects — even in test mode, a redirect to a
			// private IP from a public URL is suspicious.
			if isPrivateHost(req.URL.Hostname()) {
				return fmt.Errorf("redirect to private address %s refused", req.URL.Host)
			}
			return nil
		},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20)) // 4 MiB cap
	if err != nil {
		return "", err
	}

	content := string(body)
	if strings.Contains(resp.Header.Get("Content-Type"), "text/html") {
		content = stripHTML(content)
	}
	return content, nil
}

// isPrivateHost returns true for loopback, link-local, and RFC1918 ranges.
// Best-effort SSRF guard — a determined attacker with control of the config
// file already has shell via the repo loader's git-clone anyway.
func isPrivateHost(host string) bool {
	ips, err := net.LookupIP(host)
	if err != nil {
		return false // let the request fail naturally
	}
	for _, ip := range ips {
		if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsPrivate() {
			return true
		}
	}
	return false
}

var (
	scriptRe = regexp.MustCompile(`(?is)<script[^>]*>.*?</script>`)
	styleRe  = regexp.MustCompile(`(?is)<style[^>]*>.*?</style>`)
	tagRe    = regexp.MustCompile(`<[^>]+>`)
	wsRe     = regexp.MustCompile(`[ \t]+`)
	nlRe     = regexp.MustCompile(`\n{3,}`)
)

// stripHTML removes script/style blocks, then all remaining tags, then
// collapses whitespace. Good enough for wiki pages and rendered markdown;
// not a real HTML parser but avoids a dependency.
func stripHTML(s string) string {
	s = scriptRe.ReplaceAllString(s, "")
	s = styleRe.ReplaceAllString(s, "")
	s = tagRe.ReplaceAllString(s, " ")
	s = wsRe.ReplaceAllString(s, " ")
	s = nlRe.ReplaceAllString(s, "\n\n")
	return strings.TrimSpace(s)
}

// renderFiles wraps a set of files in a light XML-ish envelope so the model
// can tell where one file ends and the next begins. Intentionally simpler than
// the repomix format used for the scan target — no line numbers, no directory
// tree — because supplementary context is reference material, not the thing
// being audited.
func renderFiles(files []ingest.SourceFile) string {
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	var b strings.Builder
	for _, f := range files {
		fmt.Fprintf(&b, "<file path=%q>\n%s\n</file>\n", f.Path, f.Content)
	}
	return b.String()
}

// AppliesTo reports whether a loaded source should be injected into the named
// phase. Empty Phases means "all".
func (l Loaded) AppliesTo(phase string) bool {
	if len(l.Phases) == 0 {
		return true
	}
	for _, p := range l.Phases {
		if p == phase {
			return true
		}
	}
	return false
}

// FilterPhase returns the subset of loaded sources that apply to phase.
func FilterPhase(loaded []Loaded, phase string) []Loaded {
	var out []Loaded
	for _, l := range loaded {
		if l.AppliesTo(phase) {
			out = append(out, l)
		}
	}
	return out
}
