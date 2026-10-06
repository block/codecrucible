package decision

import (
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// DeploymentTrace is deterministic, best-effort context for deciding whether
// a cited operation ships and runs: callers up to an entry point, conditions
// enclosing each call, configuration keys those conditions read, and the
// repository files that set those keys. Lexical symbol matching can miss
// callers or include unrelated code, so a missing step is never evidence that
// code is unreachable or undeployed.
type DeploymentTrace struct {
	EntryPoint bool        `json:"entry_point_found"`
	Steps      []TraceStep `json:"steps,omitempty"`
	ConfigKeys []string    `json:"config_keys,omitempty"`
	Gaps       []string    `json:"gaps,omitempty"`
}

// TraceStep kinds: caller, registration, entry_point, mount, middleware,
// guard, build_constraint, config_read, config_setting.
type TraceStep struct {
	Kind string `json:"kind"`
	Note string `json:"note,omitempty"`
	Evidence
}

const (
	traceDepth    = 5
	traceCallers  = 3
	traceWindow   = 3
	traceKeys     = 8
	traceSettings = 4
	traceLineMax  = 400
)

type tracer struct {
	index    *EvidenceIndex
	deploy   map[string]string
	budget   int
	out      DeploymentTrace
	emitted  map[string]bool
	keys     []string
	keySeen  map[string]bool
	idents   []string
	identSet map[string]bool
	gapSeen  map[string]bool
	pending  []pendingGuard
	// fields are condition identifiers read as configuration members.
	fields    map[string]bool
	mountNote string
}

// DeploymentTrace walks backward from the cited sink. deploy holds
// deployment and build configuration (Dockerfiles, manifests, CI workflows)
// that may sit outside the analysis scope. budget bounds evidence text bytes.
func (index *EvidenceIndex) DeploymentTrace(cited SourceRange, deploy map[string]string, budget int) DeploymentTrace {
	t := &tracer{index: index, deploy: deploy, budget: budget, emitted: map[string]bool{}, keySeen: map[string]bool{}, identSet: map[string]bool{}, gapSeen: map[string]bool{}, fields: map[string]bool{}}
	if cited.End < cited.Start {
		cited.End = cited.Start
	}
	if _, ok := index.files[cited.Path]; !ok || cited.Start < 1 {
		t.gap("missing_source")
		return t.out
	}
	// Callers and guards come first; configuration may use what they leave.
	chain := budget * 3 / 5
	t.fileConstraints(cited.Path)
	start := index.enclosing(cited.Path, cited.Start)
	lo := 1
	if start != nil {
		lo = start.Start
	}
	t.guards(cited.Path, lo, cited.Start, chain)
	switch _, deployed := deploy[cited.Path]; {
	case deployed:
		// Build and deployment configuration applies whenever the service ships.
		t.emit("entry_point", "deployment configuration", cited.Path, cited.Start, cited.Start, chain)
		t.out.EntryPoint = true
	case start != nil && index.sources[cited.Path].parsed:
		t.climb([]*sourceUnit{start}, chain)
	default:
		// Templates, assets, and unparsed sources are reached by name.
		if !index.sources[cited.Path].parsed {
			t.gap("unparsed_source")
		} else {
			t.gap("no_enclosing_declaration")
		}
		t.climb(t.namedBy(cited.Path, "names the file", chain), chain)
	}
	if !t.out.EntryPoint {
		t.gap("entry_point_not_found")
	}
	t.resolve()
	t.settings()
	t.out.ConfigKeys = t.keys
	return t.out
}

func (t *tracer) gap(reason string) {
	if !t.gapSeen[reason] {
		t.gapSeen[reason] = true
		t.out.Gaps = append(t.out.Gaps, reason)
	}
}

// emit admits an exact source span while the text fits within limit.
func (t *tracer) emit(kind, note, path string, start, end, limit int) bool {
	content, ok := t.index.files[path]
	if !ok {
		content, ok = t.deploy[path]
	}
	if !ok {
		return false
	}
	e, ok := SourceEvidence(path, content, start, end)
	if !ok {
		return false
	}
	for _, line := range strings.Split(e.Text, "\n") {
		if len(line) > traceLineMax {
			return false // minified or generated text costs more than it explains
		}
	}
	if t.emitted[e.ID] {
		return true
	}
	cost := len(e.Text) + len(path) + len(note) + 32
	if cost > limit-t.used() {
		t.gap("trace_budget")
		return false
	}
	t.emitted[e.ID] = true
	t.out.Steps = append(t.out.Steps, TraceStep{Kind: kind, Note: note, Evidence: e})
	if kind == "guard" || kind == "build_constraint" || kind == "config_read" {
		t.collect(e.Text, kind == "guard")
	}
	return true
}

func (t *tracer) used() int {
	n := 0
	for _, s := range t.out.Steps {
		n += len(s.Text) + len(s.Path) + len(s.Note) + 32
	}
	return n
}

func (index *EvidenceIndex) enclosing(path string, line int) *sourceUnit {
	var best *sourceUnit
	for _, u := range index.sources[path].units {
		if u.header || u.container || u.Start > line || u.End < line {
			continue
		}
		if best == nil || u.End-u.Start < best.End-best.Start {
			best = u
		}
	}
	return best
}

func (index *EvidenceIndex) container(path string, line int) *sourceUnit {
	var best *sourceUnit
	for _, u := range index.sources[path].units {
		if u.container && u.Start <= line && u.End >= line && (best == nil || u.Start > best.Start) {
			best = u
		}
	}
	return best
}

type callSite struct {
	unit *sourceUnit
	line int
}

// climb follows incoming references until an entry point or the depth limit.
func (t *tracer) climb(frontier []*sourceUnit, limit int) {
	visited := map[*sourceUnit]bool{}
	live := frontier[:0]
	for _, u := range frontier {
		if u != nil && !visited[u] {
			visited[u] = true
			live = append(live, u)
		}
	}
	frontier = live
	for depth := 0; depth <= traceDepth && len(frontier) > 0; depth++ {
		var next []*sourceUnit
		push := func(u *sourceUnit) {
			if u != nil && !visited[u] {
				visited[u] = true
				next = append(next, u)
			}
		}
		for _, u := range frontier {
			kind, loaders := t.entry(u, limit)
			if kind == entryReached {
				t.out.EntryPoint = true
				continue
			}
			if kind == loadedBy {
				for _, m := range loaders {
					push(m)
				}
				continue
			}
			if depth == traceDepth {
				t.gap("trace_depth")
				continue
			}
			sites := t.index.callers(u)
			if len(sites) == 0 && depth == 0 {
				t.gap("no_callers_found")
				// The module may still be loaded and the declaration called
				// dynamically, as in handlers[name](...). Show the loaders
				// without treating them as callers.
				if u.parent == nil && filepath.Ext(u.Path) != ".go" {
					t.mountNote = "; no direct reference to the cited declaration"
					t.mounts(u.Path, limit)
					t.mountNote = ""
				}
			}
			taken := 0
			for _, site := range sites {
				if visited[site.unit] || taken == traceCallers {
					continue
				}
				taken++
				kind := "caller"
				if registrationLine(t.line(site.unit.Path, site.line)) {
					kind = "registration"
				}
				t.scope(kind, "references "+strings.Join(sortedNames(u.names), ", "), site, limit)
				push(site.unit)
			}
		}
		frontier = next
	}
}

func (t *tracer) line(path string, n int) string {
	lines := strings.Split(t.index.files[path], "\n")
	if n < 1 || n > len(lines) {
		return ""
	}
	return lines[n-1]
}

// scope shows a call site with its declaration line, enclosing conditions,
// and middleware registered before it in the same scope.
func (t *tracer) scope(kind, note string, site callSite, limit int) {
	u := site.unit
	if u.End-u.Start < 12 {
		t.emit(kind, note, u.Path, u.Start, u.End, limit)
	} else {
		if site.line-traceWindow > u.codeStart {
			t.emit(kind, "declaration", u.Path, u.codeStart, u.codeStart, limit)
		}
		t.emit(kind, note, u.Path, max(u.Start, site.line-traceWindow), min(u.End, site.line+traceWindow), limit)
	}
	t.guards(u.Path, u.Start, site.line, limit)
	added := 0
	for _, g := range t.index.sources[u.Path].units {
		if g.guard && g != u && g.parent == u.parent && g.Start < u.Start && added < 2 {
			t.emit("middleware", "registered earlier in the same scope", g.Path, g.Start, min(g.End, g.Start+traceWindow), limit)
			added++
		}
	}
}

// callers returns units that reference u's names: the same file and files
// that depend on it, nearest first. Generic short names are not followed.
func usableNames(u *sourceUnit) map[string]bool {
	names := map[string]bool{}
	for name := range u.names {
		if len(name) >= 3 && !genericNames[name] && !modifiers[name] && !controlWords[name] {
			names[name] = true
		}
	}
	return names
}

func (index *EvidenceIndex) callers(u *sourceUnit) []callSite {
	names := usableNames(u)
	if len(names) == 0 {
		return nil
	}
	paths := []string{u.Path}
	seenPath := map[string]bool{u.Path: true}
	if filepath.Ext(u.Path) == ".go" {
		for _, p := range index.packageFiles(filepath.Dir(u.Path)) {
			if !seenPath[p] {
				seenPath[p] = true
				paths = append(paths, p)
			}
		}
	}
	for _, importer := range index.reverse[u.Path] {
		// A Go import serves the whole package: siblings use its symbols
		// through fields and parameters without importing it themselves.
		related := []string{importer}
		if filepath.Ext(importer) == ".go" {
			related = index.packageFiles(filepath.Dir(importer))
		}
		for _, p := range related {
			if !seenPath[p] {
				seenPath[p] = true
				paths = append(paths, p)
			}
		}
	}
	sort.Strings(paths[1:])
	var out []callSite
	seen := map[*sourceUnit]bool{}
	for _, path := range paths {
		lines := strings.Split(index.files[path], "\n")
		for _, c := range index.sources[path].units {
			if c == u || seen[c] || c.header || c.container || !intersects(names, c.refs) || intersects(names, c.names) || c.Path == u.Path && c.Start <= u.Start && c.End >= u.End {
				continue
			}
			// Importing or re-exporting a name is not a use of it.
			if first := max(c.codeStart, c.Start); first <= len(lines) && importExportRe.MatchString(lines[first-1]) {
				continue
			}
			for n := max(c.codeStart, c.Start); n <= c.End && n <= len(lines); n++ {
				if path == u.Path && n >= u.Start && n <= u.End {
					continue
				}
				if referencesAny(lines[n-1], names) && !importExportRe.MatchString(lines[n-1]) {
					out = append(out, callSite{c, n})
					seen[c] = true
					break
				}
			}
		}
	}
	// Registrations and entry-like files first: they end the walk soonest.
	sort.SliceStable(out, func(i, j int) bool {
		return siteRank(index, out[i]) < siteRank(index, out[j])
	})
	return out
}

func (index *EvidenceIndex) packageFiles(dir string) []string {
	index.packagesOnce.Do(func() {
		index.packages = map[string][]string{}
		for path := range index.files {
			if filepath.Ext(path) == ".go" {
				index.packages[filepath.Dir(path)] = append(index.packages[filepath.Dir(path)], path)
			}
		}
	})
	return index.packages[dir]
}

func siteRank(index *EvidenceIndex, s callSite) int {
	lines := strings.Split(index.files[s.unit.Path], "\n")
	switch {
	case s.line <= len(lines) && registrationLine(lines[s.line-1]):
		return 0
	case entryFile(s.unit.Path):
		return 1
	}
	return 2
}

var genericNames = set("get", "set", "run", "new", "init", "main", "handle", "handler", "call", "apply", "next", "async", "await",
	"err", "ctx", "req", "res", "data", "value", "name", "item", "list", "test", "this", "self", "default",
	"index", "string", "error", "close", "result", "response", "request")

var importExportRe = regexp.MustCompile(`^\s*(import\b|from\s+\S+\s+import\b|export\s*\{|export\s+default\s+[\w$]+\s*;?\s*$|(module\.)?exports(\.[\w$]+)?\s*=|(const|let|var)\s*(\{[^}]*\}|[\w$]+)\s*=\s*require\(|__all__\s*=|use\s+[\w\\:]+|using\s+[\w.]+;|#\s*include\b|require(_relative|_once)?\s*\(?['"])`)

var wordRe = regexp.MustCompile(`[A-Za-z_$][A-Za-z0-9_$]*`)

func referencesAny(line string, names map[string]bool) bool {
	for _, w := range wordRe.FindAllString(stripCode(line), -1) {
		if names[w] {
			return true
		}
	}
	return false
}

func sortedNames(names map[string]bool) []string {
	out := make([]string, 0, len(names))
	for n := range names {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

var registrationRe = regexp.MustCompile(`[.:>]\s*(get|post|put|patch|delete|del|all|head|options|route|any|use|Get|Post|Put|Patch|Delete|Any|Handle|HandleFunc|Handler|Method|Methods|Group|Route|Mount|MapGet|MapPost|MapPut|MapDelete|add_url_rule|add_api_route|register_blueprint|include_router|addServlet|addFilter|register)\s*\(|^\s*(re_)?path\s*\(|^\s*url\s*\(`)

func registrationLine(line string) bool { return registrationRe.MatchString(stripCode(line)) }

var entryAnnotations = set("route", "get", "post", "put", "patch", "delete", "websocket", "GetMapping",
	"PostMapping", "PutMapping", "DeleteMapping", "PatchMapping", "RequestMapping", "WebServlet", "WebFilter",
	"WebListener", "Path", "GET", "POST", "PUT", "DELETE", "PATCH", "Scheduled", "KafkaListener",
	"RabbitListener", "JmsListener", "SqsListener", "EventListener", "StreamListener", "MessageMapping",
	"api_view", "action", "task", "shared_task", "command", "HttpGet", "HttpPost", "HttpPut", "HttpDelete",
	"HttpPatch", "Route", "on_event", "on", "listener", "cron", "SpringBootApplication", "Controller",
	"RestController", "ApiController", "Command", "Get", "Post", "Put", "Delete", "Patch", "UrlBinding",
	"HandlesEvent", "DefaultHandler", "WebServlet", "Endpoint", "PayloadRoot", "WebMethod", "GrpcService")

var annotationRe = regexp.MustCompile(`^\s*(@|#\[|\[)\s*([A-Za-z_][\w.]*)`)

var funcDeclRe = regexp.MustCompile(`^\s*(export\s+)?(default\s+)?(public\s+|private\s+|protected\s+|static\s+|async\s+)*(function\b|def\s|func\s|fn\s|fun\s|sub\s)|=>|\bfunction\s*\(|\blambda\b`)

type entryKind int

const (
	notEntry entryKind = iota
	entryReached
	// loadedBy: u runs when something else loads or registers it; the walk
	// continues from those sites.
	loadedBy
)

// entry classifies u and emits its evidence. Process mains and annotated
// handlers are entry points. Framework callbacks run when their class is
// registered, and module-level code when its module loads: in an entry file
// that is an entry point; elsewhere their registrations and loaders are
// traced instead.
func (t *tracer) entry(u *sourceUnit, limit int) (entryKind, []*sourceUnit) {
	goFile := filepath.Ext(u.Path) == ".go"
	if u.names["main"] && u.function || goFile && u.names["init"] && u.function {
		t.emit("entry_point", "process entry", u.Path, u.codeStart, u.codeStart, limit)
		return entryReached, nil
	}
	if t.annotations(u, limit) {
		return entryReached, nil
	}
	if u.parent != nil && t.callback(u) {
		t.emit("framework_callback", "invoked by the framework once the class is registered", u.Path, u.codeStart, t.declLine(u), limit)
		if t.managed(u.parent, limit) || t.registeredClass(u.parent, limit) {
			return entryReached, nil
		}
		if sites := t.instantiations(u.parent, limit); len(sites) > 0 {
			return loadedBy, sites
		}
		t.gap("callback_registration_not_found")
		return notEntry, nil
	}
	if served(u.Path) {
		t.emit("entry_point", "page served directly from the web root", u.Path, u.codeStart, u.codeStart, limit)
		return entryReached, nil
	}
	if goFile || u.parent != nil || u.header || u.container {
		return notEntry, nil
	}
	first := t.line(u.Path, u.codeStart)
	if len(usableNames(u)) > 0 && u.function && funcDeclRe.MatchString(first) && !registrationLine(first) {
		return notEntry, nil
	}
	end := min(u.End, u.codeStart+traceWindow)
	if entryFile(u.Path) || t.launched(u.Path) {
		t.emit("entry_point", "module-level statement in an entry file", u.Path, u.codeStart, end, limit)
		return entryReached, nil
	}
	t.emit("module_level", "runs when the module is loaded", u.Path, u.codeStart, end, limit)
	return loadedBy, t.mounts(u.Path, limit)
}

var servedRoot = regexp.MustCompile(`(^|/)(webcontent|webapp|web|public|public_html|www|htdocs|static)/`)

// served reports server pages the web container exposes by path; files
// under WEB-INF or META-INF are reachable only through a forward.
func served(path string) bool {
	lower := strings.ToLower(path)
	switch filepath.Ext(lower) {
	case ".jsp", ".jspx", ".php", ".asp", ".aspx", ".cfm", ".erb":
	default:
		return false
	}
	return servedRoot.MatchString(lower) && !strings.Contains(lower, "web-inf/") && !strings.Contains(lower, "meta-inf/")
}

var callbackMethods = set("doGet", "doPost", "doPut", "doDelete", "doHead", "doOptions", "doPatch", "service",
	"doFilter", "doFilterInternal", "init", "destroy", "contextInitialized", "contextDestroyed", "preHandle",
	"postHandle", "afterCompletion", "addInterceptors", "addCorsMappings", "addResourceHandlers", "configure",
	"filterChain", "securityFilterChain", "onStartup", "afterPropertiesSet", "onApplicationEvent", "handle",
	"handleRequest", "intercept", "onMessage", "sessionCreated", "attributeAdded", "requestInitialized",
	"OnActionExecuting", "OnActionExecuted", "OnAuthorization", "InvokeAsync", "Invoke", "Configure", "ConfigureServices")

// callback reports a method a framework calls on a registered type: a known
// callback name in a type that implements or extends something.
func (t *tracer) callback(u *sourceUnit) bool {
	named := false
	for name := range u.names {
		named = named || callbackMethods[name]
	}
	if !named {
		return false
	}
	header := strings.Join(strings.Split(t.index.files[u.Path], "\n")[u.parent.Start-1:u.parent.End], " ")
	return regexp.MustCompile(`\b(implements|extends)\b|\)\s*:|\w\s*:\s*\w`).MatchString(stripCode(header))
}

var componentAnnotations = set("Component", "Configuration", "Service", "Controller", "RestController",
	"Repository", "WebFilter", "WebServlet", "WebListener", "Named", "Singleton", "Provider",
	"SpringBootApplication", "ControllerAdvice", "RestControllerAdvice", "EnableWebSecurity", "EnableWebMvc",
	"Path", "ApiController", "Injectable", "Module", "Configurable", "ServerEndpoint")

// managed reports a class the framework instantiates itself.
func (t *tracer) managed(class *sourceUnit, limit int) bool {
	lines := strings.Split(t.index.files[class.Path], "\n")
	for n := class.Start; n <= class.End && n <= len(lines); n++ {
		if m := annotationRe.FindStringSubmatch(lines[n-1]); m != nil && componentAnnotations[m[2][strings.LastIndex(m[2], ".")+1:]] {
			t.emit("entry_point", "framework-managed class", class.Path, n, n, limit)
			return true
		}
	}
	return false
}

// instantiations finds where source creates or names the class for
// registration: new X(), X.class, X::new, typeof(X).
func (t *tracer) instantiations(class *sourceUnit, limit int) []*sourceUnit {
	var out []*sourceUnit
	for _, name := range sortedNames(usableNames(class)) {
		re := regexp.MustCompile(`\bnew\s+` + name + `\b|\b` + name + `\.class\b|\b` + name + `::new\b|typeof\(\s*` + name + `\s*\)|<\s*` + name + `\s*>`)
		for _, path := range sortedKeys(t.index.files) {
			for i, line := range strings.Split(t.index.files[path], "\n") {
				if len(out) >= traceCallers {
					return out
				}
				if path == class.Path && i+1 >= class.Start && i+1 <= class.End || !re.MatchString(stripCode(line)) || importExportRe.MatchString(line) {
					continue
				}
				unit := t.index.enclosing(path, i+1)
				if unit == nil {
					continue
				}
				t.scope("registration", "creates or registers "+name, callSite{unit, i + 1}, limit)
				out = append(out, unit)
			}
		}
	}
	return out
}

// launched reports whether deployment configuration names the file, as in a
// Dockerfile CMD, a Procfile, or package.json scripts.
func (t *tracer) launched(path string) bool {
	re := regexp.MustCompile(`(^|[^\w./-])(\./)?` + regexp.QuoteMeta(path) + `\b`)
	for _, content := range t.deploy {
		if re.MatchString(content) {
			return true
		}
	}
	return false
}

// annotations emits deployment conditions and entry annotations on u and its
// enclosing types, such as @Profile("dev"), #[cfg(...)], or @app.route.
func (t *tracer) annotations(u *sourceUnit, limit int) bool {
	entry := false
	lines := strings.Split(t.index.files[u.Path], "\n")
	for scope := u; scope != nil; scope = scope.parent {
		for n := scope.Start; n <= scope.End && n <= len(lines) && n < scope.Start+12; n++ {
			text := strings.TrimSpace(lines[n-1])
			if text == "" || strings.HasPrefix(text, "//") || strings.HasPrefix(text, "*") || strings.HasPrefix(text, "/*") || strings.HasPrefix(text, "#") && !strings.HasPrefix(text, "#[") {
				continue
			}
			m := annotationRe.FindStringSubmatch(lines[n-1])
			if m == nil {
				break
			}
			name := m[2]
			if i := strings.LastIndex(name, "."); i >= 0 {
				name = name[i+1:]
			}
			switch {
			case deployAnnotationRe.MatchString(lines[n-1]):
				t.emit("guard", "deployment condition on the declaration", u.Path, n, n, limit)
			case scope == u && entryAnnotations[name]:
				t.emit("entry_point", "annotated handler", u.Path, n, n, limit)
				entry = true
			}
		}
	}
	return entry
}

var deployAnnotationRe = regexp.MustCompile(`@(Profile|Conditional\w*|ActiveProfiles|EnabledIf\w*|IfBuildProfile|IfProfile)\b|#\[cfg\b|#\[cfg_attr\b|\[Conditional\(`)

// registeredClass looks for deployment descriptors naming the class.
func (t *tracer) registeredClass(class *sourceUnit, limit int) bool {
	names := sortedNames(usableNames(class))
	if len(names) == 0 {
		return false
	}
	found := 0
	for _, path := range sortedKeys(t.deploy) {
		if !strings.HasSuffix(path, ".xml") {
			continue
		}
		for i, line := range strings.Split(t.deploy[path], "\n") {
			for _, name := range names {
				if strings.Contains(line, "."+name+"<") || strings.Contains(line, ">"+name+"<") {
					t.emit("registration", "deployment descriptor names "+name, path, i+1, i+1, limit)
					found++
				}
			}
			if found >= 2 {
				return true
			}
		}
	}
	return found > 0
}

// mounts finds where other files load a module: imports, then uses of the
// imported binding, or quoted references when nothing imports it. It returns
// the declarations containing those sites so the walk can continue upward.
func (t *tracer) mounts(path string, limit int) []*sourceUnit {
	stem := moduleStem(path)
	if stem == "" {
		return nil
	}
	q := regexp.QuoteMeta(stem)
	modRe := regexp.MustCompile(`(["'/.])` + q + `(\.\w+)?["']|\bimport\s+[\w.]*\b` + q + `\b|\bfrom\s+[\w.]*\b` + q + `\b|from\s+[\w.]+\s+import\s+.*\b` + q + `\b`)
	candidates := append([]string{}, t.index.reverse[path]...)
	sort.Strings(candidates)
	var out []*sourceUnit
	found := 0
	for _, importer := range candidates {
		if importer == path || found >= 2 {
			continue
		}
		lines := strings.Split(t.index.files[importer], "\n")
		for i, line := range lines {
			if !modRe.MatchString(line) || !loadsRe.MatchString(line) {
				continue
			}
			found++
			binding := ""
			if m := bindingRe.FindStringSubmatch(line); m != nil {
				binding = firstNonEmpty(m[1:])
			}
			uses := 0
			// The imported binding is usually mounted on a later line.
			for j := i + 1; binding != "" && j < len(lines) && uses < 2; j++ {
				if referencesAny(lines[j], map[string]bool{binding: true}) {
					out = append(out, t.mountSite(importer, j+1, "uses the module loaded at line "+strconv.Itoa(i+1), limit))
					uses++
				}
			}
			if uses == 0 {
				out = append(out, t.mountSite(importer, i+1, "loads the module", limit))
			}
			break
		}
	}
	if found == 0 {
		out = t.namedBy(path, "names the module", limit)
	}
	if len(out) == 0 {
		t.gap("module_loader_not_found")
	}
	return out
}

var stemWordRe = regexp.MustCompile(`[A-Za-z]{3}`)

// moduleStem is the name other files use for a module. Numeric names
// (404.jsp) also match unrelated literals and are not searched.
func moduleStem(path string) string {
	stem := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
	if stem == "index" || stem == "__init__" || stem == "mod" {
		stem = filepath.Base(filepath.Dir(path))
	}
	if !stemWordRe.MatchString(stem) {
		return ""
	}
	return stem
}

// namedBy finds quoted references to a file by name, such as a template
// rendered by res.render('task-detail') or a URLconf named 'app.urls'.
func (t *tracer) namedBy(path, note string, limit int) []*sourceUnit {
	stem := moduleStem(path)
	if stem == "" {
		return nil
	}
	pattern := `["'/.]` + regexp.QuoteMeta(stem) + `(\.\w+)*["']`
	if ext := filepath.Ext(path); ext == ".tag" || ext == ".tagx" {
		pattern = `<[\w-]+:` + regexp.QuoteMeta(stem) + `\b` // JSP tag files are used as <prefix:name>
	}
	re := regexp.MustCompile(pattern)
	type ref struct {
		path string
		line int
	}
	var preferred, other []ref
	for _, p := range sortedKeys(t.index.files) {
		if p == path {
			continue
		}
		first := 0
		for i, line := range strings.Split(t.index.files[p], "\n") {
			if !re.MatchString(line) || importExportRe.MatchString(line) {
				continue
			}
			if renderRe.MatchString(line) || strings.HasPrefix(pattern, "<") {
				preferred = append(preferred, ref{p, i + 1})
				first = -1
				break
			}
			if first == 0 {
				first = i + 1
			}
		}
		if first > 0 {
			other = append(other, ref{p, first})
		}
	}
	// Render and include calls name templates; links and redirects only
	// share their spelling.
	refs := preferred
	if len(refs) == 0 {
		refs = other
	}
	// A directly served page ends the trace in one step.
	sort.SliceStable(refs, func(i, j int) bool { return served(refs[i].path) && !served(refs[j].path) })
	var out []*sourceUnit
	for _, r := range refs[:min(len(refs), traceCallers)] {
		out = append(out, t.mountSite(r.path, r.line, note, limit))
	}
	return out
}

var loadsRe = regexp.MustCompile(`\brequire\s*\(|\bimport\b|\bfrom\s|\binclude\b|\bload\b|@import|\bmod\s|\buse\s`)

var renderRe = regexp.MustCompile(`(?i)render|template|include|partial|layout|view|extends|import|require|load|forward|dispatch|resolution|src=|href=["'][^"']*\.(css|js)`)

func (t *tracer) mountSite(path string, n int, note string, limit int) *sourceUnit {
	u := t.index.enclosing(path, n)
	if u == nil {
		u = t.index.container(path, n) // a class-level annotation such as @UrlBinding
	}
	lo := 1
	if u != nil {
		lo = u.Start
	}
	t.emit("mount", note+t.mountNote, path, n, n, limit)
	t.guards(path, lo, n, limit)
	return u
}

// fileConstraints emits build constraints that decide whether the file is
// compiled at all.
func (t *tracer) fileConstraints(path string) {
	lines := strings.Split(t.index.files[path], "\n")
	for i, line := range lines {
		if i > 40 {
			break
		}
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "//go:build") || strings.HasPrefix(trimmed, "// +build") || strings.HasPrefix(trimmed, "#![cfg") {
			t.emit("build_constraint", "file compiled only when satisfied", path, i+1, i+1, t.budget)
		}
	}
}

var conditionRe = regexp.MustCompile(`^\s*\}?\s*(if|else|elif|elsif|unless|when|switch|case|match|guard|select)\b|^\s*\}?\s*else\b|\bif\s*\(|\bif\s+let\b`)

// guards emits conditions enclosing line within [lo, line]: brace blocks,
// indentation blocks, and preprocessor regions.
func (t *tracer) guards(path string, lo, line, limit int) {
	lines := strings.Split(t.index.files[path], "\n")
	if line > len(lines) {
		return
	}
	var headers []int
	if braced(path) {
		headers = braceConditions(lines, lo, line)
	} else {
		headers = indentConditions(lines, lo, line)
	}
	if preprocessed(path) {
		headers = append(headers, preprocessorConditions(lines, line)...)
	}
	sort.Ints(headers)
	for _, n := range headers {
		text := lines[n-1]
		if ppRe.MatchString(text) || configCondition(text) {
			t.emit("guard", "encloses line "+strconv.Itoa(line), path, n, n, limit)
			continue
		}
		// Plain conditions matter only if they test a configured value.
		t.pending = append(t.pending, pendingGuard{path, n, line, limit})
		code := stripCode(text)
		for _, loc := range wordRe.FindAllStringIndex(code, -1) {
			w := code[loc[0]:loc[1]]
			// Member names (req.body.x) are not variables defined from config.
			if loc[0] > 0 && code[loc[0]-1] == '.' || len(w) < 4 || controlWords[w] || keyStop[w] || genericNames[w] {
				continue
			}
			t.ident(w)
		}
	}
}

type pendingGuard struct {
	path              string
	line, site, limit int
}

func configCondition(text string) bool {
	code := stripCode(text)
	return readsConfig(text) || configFieldRe.MatchString(code) || envNameRe.MatchString(code) || strings.Contains(code, "cfg!(") || strings.Contains(code, "debug_assertions")
}

func braced(path string) bool {
	ext := filepath.Ext(path)
	return ext == ".go" || braceLanguages[ext] != nil
}

func preprocessed(path string) bool {
	switch filepath.Ext(path) {
	case ".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh", ".m", ".mm", ".cs", ".swift":
		return true
	}
	return false
}

var quotedRe = regexp.MustCompile(`"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|` + "`[^`]*`")

// stripCode removes string literals and line comments, enough to count
// braces and identifiers on one line.
func stripCode(line string) string {
	line = quotedRe.ReplaceAllString(line, `""`)
	if i := strings.Index(line, "//"); i >= 0 {
		line = line[:i]
	}
	return line
}

func braceConditions(lines []string, lo, line int) []int {
	var out []int
	if conditionRe.MatchString(lines[line-1]) {
		out = append(out, line)
	}
	level, chain := 0, false
	for n := line - 1; n >= max(lo, 1); n-- {
		code := stripCode(lines[n-1])
		for i := len(code) - 1; i >= 0; i-- {
			switch code[i] {
			case '}':
				level++
			case '{':
				if level > 0 {
					level--
					if level == 0 && chain {
						// The opener of the if-chain this else branch belongs to.
						out = append(out, n)
						chain = strings.HasPrefix(strings.TrimSpace(code), "}")
						if chain {
							level++ // keep following "} else if" toward its if
						}
					}
					continue
				}
				if conditionRe.MatchString(code) {
					out = append(out, n)
					if strings.HasPrefix(strings.TrimSpace(code), "}") {
						chain = true
					}
				}
			}
		}
	}
	return dedupe(out)
}

func indentConditions(lines []string, lo, line int) []int {
	indent := func(s string) int { return len(s) - len(strings.TrimLeft(s, " \t")) }
	var out []int
	current := indent(lines[line-1])
	chainIndent := -1
	for n := line - 1; n >= max(lo, 1); n-- {
		text := lines[n-1]
		trimmed := strings.TrimSpace(text)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		in := indent(text)
		if chainIndent >= 0 && in == chainIndent {
			if regexp.MustCompile(`^(if|elif|elsif|unless|case|when)\b`).MatchString(trimmed) {
				out = append(out, n)
				if strings.HasPrefix(trimmed, "if") || strings.HasPrefix(trimmed, "unless") || strings.HasPrefix(trimmed, "case") {
					chainIndent = -1
				}
			}
			continue
		}
		if in >= current {
			continue
		}
		current = in
		if conditionRe.MatchString(trimmed) {
			out = append(out, n)
			if regexp.MustCompile(`^(else|elif|elsif|when)\b`).MatchString(trimmed) {
				chainIndent = in
			}
		}
		if in == 0 {
			break
		}
	}
	return out
}

var ppRe = regexp.MustCompile(`^\s*#\s*(if|ifdef|ifndef|elif|else|endif)\b`)

func preprocessorConditions(lines []string, line int) []int {
	var out []int
	level := 0
	for n := line - 1; n >= 1; n-- {
		m := ppRe.FindStringSubmatch(lines[n-1])
		if m == nil {
			continue
		}
		switch m[1] {
		case "endif":
			level++
		case "if", "ifdef", "ifndef":
			if level > 0 {
				level--
				continue
			}
			// Include guards fence the whole header, not a configuration.
			if m[1] == "ifndef" && n < len(lines) && strings.HasPrefix(strings.TrimSpace(lines[n]), "#define") {
				continue
			}
			out = append(out, n)
		case "elif", "else":
			if level == 0 {
				out = append(out, n)
			}
		}
	}
	return out
}

func dedupe(lines []int) []int {
	seen := map[int]bool{}
	out := lines[:0]
	for _, n := range lines {
		if !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	return out
}

// Configuration reads with a literal key, by language.
var keyRes = []*regexp.Regexp{
	regexp.MustCompile(`(?:Getenv|LookupEnv|getenv|environ\.get|environ\[|getProperty|GetEnvironmentVariable|env::var|env::var_os|ENV\.fetch|ENV\[|\$_ENV\[|\$_SERVER\[|\benv\(|\bconfig\(|Config\.get|viper\.\w+|\bGetBool|\bGetString|\bIsSet|settings\.get|config\.get|app\.config\.get|app\.config\[|process\.env\[|getBoolean|getString|\.Value<\w+>\()\s*\(?\s*["'` + "`" + `]([A-Za-z][A-Za-z0-9_.:-]*)["'` + "`" + `]`),
	regexp.MustCompile(`\b(?:process|import\.meta)\.env\.([A-Za-z_][A-Za-z0-9_]*)`),
	regexp.MustCompile(`\bflag\.\w+\(\s*(?:&[\w.]+,\s*)?"([^"]+)"`),
	regexp.MustCompile(`add_argument\(\s*["']--([\w-]+)`),
	regexp.MustCompile(`@Value\(\s*"\$\{([^:}]+)`),
	regexp.MustCompile(`(?:name|value|prefix|havingValue)\s*=\s*\{?\s*"([\w.-]+)"`),
	regexp.MustCompile(`cfg!?\(\s*feature\s*=\s*"([^"]+)"`),
	regexp.MustCompile(`\b(debug_assertions)\b`),
	regexp.MustCompile(`^\s*#\s*(?:ifdef|ifndef|if|elif)\s+!?\s*(?:defined\s*\(?\s*)?([A-Za-z_]\w*)`),
	regexp.MustCompile(`\b(?:env|mapstructure|toml|envconfig|koanf|default)[:=]"([A-Za-z][\w.-]*)`),
	regexp.MustCompile(`(?:isEnabled|isActive|isFeatureEnabled|isFeatureActive|featureEnabled|isOn|enabled\?|boolVariation|stringVariation|jsonVariation|variation|getTreatment|isEnabledFor|IsEnabled|IsEnabledAsync)\(\s*:?["']([\w.:-]+)`),
	featureEnumRe,
}

// Enum-style flags: FeatureFlags.API_AUTO_AUTHENTICATE.isActive().
var featureEnumRe = regexp.MustCompile(`\b\w*(?:Feature|Flag|Toggle)\w*\.([A-Z][A-Z0-9_]{2,})\b`)

var profileRe = regexp.MustCompile(`@(?:Profile|ActiveProfiles)\(\s*\{?\s*"([\w-]+)"`)
var buildTagRe = regexp.MustCompile(`^\s*(?://go:build|// \+build)\s+(.+)`)
var configFieldRe = regexp.MustCompile(`\b(?:cfg|conf|config|configuration|settings|options|opts|flags|features|featureFlags|Config|Settings|Options|AppConfig|appConfig|env)\.([A-Za-z_]\w*)`)
var envNameRe = regexp.MustCompile(`\bRails\.env\.\w+\?|\bIsDevelopment\(\)|\bIsProduction\(\)|\bIsStaging\(\)`)

var keyStop = set("true", "false", "null", "nil", "None", "undefined", "json", "yaml", "get", "set", "string")

func (t *tracer) addKey(key string) {
	key = strings.TrimSpace(key)
	if key == "" || keyStop[key] || len(t.keys) >= traceKeys || t.keySeen[normKey(key)] {
		return
	}
	t.keySeen[normKey(key)] = true
	t.keys = append(t.keys, key)
}

// collect extracts configuration keys from guard and read text. Identifiers
// in conditions are kept for one level of definition lookup.
func (t *tracer) collect(text string, conditions bool) {
	for _, line := range strings.Split(text, "\n") {
		for _, re := range keyRes {
			for _, m := range re.FindAllStringSubmatch(line, -1) {
				t.addKey(m[1])
			}
		}
		if m := profileRe.FindStringSubmatch(line); m != nil {
			t.addKey("spring.profiles.active")
			t.addKey(m[1])
		}
		if m := buildTagRe.FindStringSubmatch(line); m != nil {
			for _, tag := range wordRe.FindAllString(m[1], -1) {
				t.addKey(tag)
			}
		}
		if m := envNameRe.FindString(line); m != "" {
			if strings.HasPrefix(m, "Rails") {
				t.addKey("RAILS_ENV")
			} else {
				t.addKey("ASPNETCORE_ENVIRONMENT")
			}
		}
		for _, m := range featureEnumRe.FindAllStringSubmatch(line, -1) {
			t.ident(m[1])
			t.fields[m[1]] = true
		}
		if !conditions || !conditionRe.MatchString(line) {
			continue
		}
		for _, m := range configFieldRe.FindAllStringSubmatch(stripCode(line), -1) {
			t.addKey(m[1])
			t.ident(m[1])
			t.fields[m[1]] = true
		}
	}
}

func (t *tracer) ident(name string) {
	if !t.identSet[name] && len(t.idents) < 12 {
		t.identSet[name] = true
		t.idents = append(t.idents, name)
	}
}

// resolve finds where condition identifiers are defined from configuration:
// `debug := os.Getenv("DEBUG")`, `Debug bool env:"DEBUG"`, `debug: process.env.X`.
func (t *tracer) resolve() {
	if len(t.idents) == 0 {
		return
	}
	var paths []string
	seen := map[string]bool{}
	for _, s := range t.out.Steps {
		if _, ok := t.index.files[s.Path]; ok && !seen[s.Path] {
			seen[s.Path] = true
			paths = append(paths, s.Path)
			for _, dep := range t.index.graph[s.Path] {
				if !seen[dep] {
					seen[dep] = true
					paths = append(paths, dep)
				}
			}
		}
	}
	for _, g := range t.pending {
		if !seen[g.path] {
			seen[g.path] = true
			paths = append(paths, g.path)
		}
	}
	for _, path := range sortedKeys(t.index.files) {
		base := strings.ToLower(filepath.Base(path))
		if !seen[path] && configFileRe.MatchString(base) {
			seen[path] = true
			paths = append(paths, path)
		}
	}
	found := 0
	configured := map[string]bool{}
	for _, ident := range append([]string{}, t.idents...) {
		// Configuration members may be object or YAML keys; variables need
		// an assignment or a tagged struct field.
		forms := `:=|=[^=]|\s+\w+.*` + "`" + `|\?\?=`
		if t.fields[ident] {
			forms += `|:\s|\s*[(,;{]|\s*$` // object and YAML keys, enum constants
		}
		def := regexp.MustCompile(`(^|[^\w.])` + regexp.QuoteMeta(ident) + `\b\s*(` + forms + `)`)
		for _, path := range paths {
			for i, line := range strings.Split(t.index.files[path], "\n") {
				if found >= traceKeys || !def.MatchString(line) || !readsConfig(line) && !(t.fields[ident] && configFileRe.MatchString(strings.ToLower(filepath.Base(path)))) {
					continue
				}
				if t.emit("config_read", ident+" is read from configuration", path, i+1, i+1, t.budget) {
					found++
					configured[ident] = true
				}
			}
		}
	}
	for _, g := range t.pending {
		if referencesAny(t.line(g.path, g.line), configured) {
			t.emit("guard", "encloses line "+strconv.Itoa(g.site)+"; tests a configured value", g.path, g.line, g.line, t.budget)
		}
	}
}

var configFileRe = regexp.MustCompile(`(config|settings|conf|env|options|flags|feature)`)

func readsConfig(line string) bool {
	for _, re := range keyRes {
		if re.MatchString(line) {
			return true
		}
	}
	return false
}

func normKey(key string) string {
	return strings.NewReplacer("_", "", "-", "", ".", "", ":", "").Replace(strings.ToLower(key))
}

var settingTokenRe = regexp.MustCompile(`[A-Za-z0-9_.:-]+`)

// settings finds lines in deployment and build configuration that name each
// key. Keys found nowhere are reported, since the repository does not show
// how the deployed environment sets them.
func (t *tracer) settings() {
	paths := sortedKeys(t.deploy)
	for _, key := range t.keys {
		want := normKey(key)
		found := 0
		for _, path := range paths {
			lines := strings.Split(t.deploy[path], "\n")
			for i, line := range lines {
				if found >= traceSettings {
					break
				}
				match := false
				for _, tok := range settingTokenRe.FindAllString(line, -1) {
					tok = strings.TrimPrefix(tok, "-D") // compiler defines
					tok = strings.Trim(tok, ".:-")
					if normKey(tok) == want || strings.HasPrefix(normKey(tok), want+"=") {
						match = true
						break
					}
				}
				if !match || strings.Contains(strings.ToLower(line), "secret") && !strings.Contains(line, "${{") {
					continue
				}
				end := i + 1
				// Kubernetes-style env lists put the value on the next line.
				if strings.Contains(line, "name:") && i+1 < len(lines) && strings.Contains(lines[i+1], "value") {
					end = i + 2
				}
				if t.emit("config_setting", "sets or passes "+key, path, i+1, end, t.budget) {
					found++
				}
			}
		}
		if found == 0 {
			t.gap("config_key_not_set_in_repo:" + key)
		}
	}
}

// declLine is the line naming the unit, after any annotations.
func (t *tracer) declLine(u *sourceUnit) int {
	for n := u.codeStart; n <= min(u.End, u.codeStart+traceWindow*2); n++ {
		for _, w := range wordRe.FindAllString(t.line(u.Path, n), -1) {
			if u.names[w] {
				return n
			}
		}
	}
	return u.codeStart
}

func entryFile(path string) bool {
	base := strings.ToLower(filepath.Base(path))
	switch strings.TrimSuffix(base, filepath.Ext(base)) {
	case "main", "server", "app", "index", "wsgi", "asgi", "manage", "program", "startup", "application", "urls", "routes", "router":
		return true
	}
	return false
}

var bindingRe = regexp.MustCompile(`(?:const|let|var)\s+(\w+)\s*=\s*require\(|import\s+(\w+)\s+from\b|import\s+\*\s+as\s+(\w+)|from\s+[\w.]+\s+import\s+(\w+)\s*$|^\s*(\w+)\s*=\s*require\(`)

func firstNonEmpty(values []string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
