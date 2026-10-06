package decision

import (
	"reflect"
	"slices"
	"strings"
	"testing"
)

func traceOf(t *testing.T, files map[string]string, graph map[string][]string, deploy map[string]string, path string, line int) DeploymentTrace {
	t.Helper()
	index := NewEvidenceIndex(files, graph)
	trace := index.DeploymentTrace(SourceRange{Path: path, Start: line, End: line}, deploy, 20000)
	if !reflect.DeepEqual(trace, index.DeploymentTrace(SourceRange{Path: path, Start: line, End: line}, deploy, 20000)) {
		t.Fatal("nondeterministic trace")
	}
	return trace
}

// step finds the first step of kind whose text contains want.
func step(trace DeploymentTrace, kind, want string) *TraceStep {
	for i, s := range trace.Steps {
		if s.Kind == kind && strings.Contains(s.Text, want) {
			return &trace.Steps[i]
		}
	}
	return nil
}

func requireStep(t *testing.T, trace DeploymentTrace, kind, want string) {
	t.Helper()
	if step(trace, kind, want) == nil {
		t.Fatalf("no %s step containing %q in %+v", kind, want, trace)
	}
}

func TestDeploymentTraceGoRouteReachesMainAndEnvSetting(t *testing.T) {
	files := map[string]string{
		"cmd/main.go": "package main\n\nfunc main() {\n\thttp.HandleFunc(\"/debug\", debugHandler)\n\thttp.ListenAndServe(\":8080\", nil)\n}\n",
		"cmd/debug.go": "package main\n\nfunc debugHandler(w http.ResponseWriter, r *http.Request) {\n" +
			"\tif os.Getenv(\"ENABLE_DEBUG\") == \"1\" {\n\t\texec.Command(r.URL.Query().Get(\"cmd\")).Run()\n\t}\n}\n",
	}
	deploy := map[string]string{"deploy/app.yaml": "env:\n  - name: ENABLE_DEBUG\n    value: \"1\"\n", "Dockerfile": "FROM scratch\n"}
	trace := traceOf(t, files, nil, deploy, "cmd/debug.go", 5)
	if !trace.EntryPoint || len(trace.Gaps) != 0 {
		t.Fatalf("expected a complete trace: %+v", trace)
	}
	requireStep(t, trace, "guard", `os.Getenv("ENABLE_DEBUG")`)
	requireStep(t, trace, "registration", "http.HandleFunc")
	requireStep(t, trace, "config_setting", "ENABLE_DEBUG")
	if !slices.Equal(trace.ConfigKeys, []string{"ENABLE_DEBUG"}) {
		t.Fatalf("config keys = %v", trace.ConfigKeys)
	}
}

func TestDeploymentTraceExpressMountReachesServer(t *testing.T) {
	files := map[string]string{
		"server.js":       "const express = require('express');\nconst app = express();\napp.use('/admin', require('./routes/admin'));\napp.listen(3000);\n",
		"routes/admin.js": "const router = require('express').Router();\n\nrouter.get('/run', (req, res) => {\n  eval(req.query.code);\n});\n\nmodule.exports = router;\n",
		"package.json":    "{\"main\": \"server.js\"}\n",
	}
	graph := map[string][]string{"server.js": {"routes/admin.js"}}
	trace := traceOf(t, files, graph, nil, "routes/admin.js", 4)
	if !trace.EntryPoint {
		t.Fatalf("express route not traced to the server: %+v", trace)
	}
	requireStep(t, trace, "module_level", "router.get('/run'")
	requireStep(t, trace, "mount", "app.use('/admin'")
}

func TestDeploymentTraceTemplateReachedByRender(t *testing.T) {
	files := map[string]string{
		"views/profile.ejs": "<h1>Profile</h1>\n<div><%- user.bio %></div>\n",
		"app.js":            "const app = require('express')();\napp.get('/profile', (req, res) => res.render('profile', { user: req.user }));\napp.listen(3000);\n",
	}
	trace := traceOf(t, files, nil, nil, "views/profile.ejs", 2)
	if !trace.EntryPoint || !slices.Contains(trace.Gaps, "unparsed_source") {
		t.Fatalf("template not traced by name: %+v", trace)
	}
	requireStep(t, trace, "mount", "res.render('profile'")
}

func TestDeploymentTraceFeatureFlagGuardReportsUnsetKey(t *testing.T) {
	files := map[string]string{
		"src/app/FeatureFlags.java": "package app;\n\npublic enum FeatureFlags {\n    AUTO_LOGIN(\"auto-login\");\n\n" +
			"    private final String key;\n    FeatureFlags(String key) { this.key = key; }\n" +
			"    public boolean isActive() { return client.boolVariation(key, false); }\n}\n",
		"src/app/LoginInterceptor.java": "package app;\n\npublic class LoginInterceptor implements HandlerInterceptor {\n" +
			"    @Override\n    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) {\n" +
			"        if (FeatureFlags.AUTO_LOGIN.isActive()) {\n            session.login(request.getParameter(\"user\"));\n        }\n        return true;\n    }\n}\n",
		"src/app/WebConfig.java": "package app;\n\n@Configuration\npublic class WebConfig implements WebMvcConfigurer {\n" +
			"    @Override\n    public void addInterceptors(InterceptorRegistry registry) {\n        registry.addInterceptor(new LoginInterceptor());\n    }\n}\n",
	}
	trace := traceOf(t, files, nil, map[string]string{"pom.xml": "<project/>\n"}, "src/app/LoginInterceptor.java", 7)
	if !trace.EntryPoint {
		t.Fatalf("interceptor not traced to its registration: %+v", trace)
	}
	requireStep(t, trace, "guard", "FeatureFlags.AUTO_LOGIN.isActive()")
	requireStep(t, trace, "framework_callback", "preHandle")
	requireStep(t, trace, "registration", "new LoginInterceptor()")
	if !slices.Contains(trace.ConfigKeys, "AUTO_LOGIN") || !slices.Contains(trace.Gaps, "config_key_not_set_in_repo:AUTO_LOGIN") {
		t.Fatalf("flag key not reported as unset: %+v", trace)
	}
}

func TestDeploymentTraceServletCallbackRegisteredByDescriptor(t *testing.T) {
	files := map[string]string{
		"src/app/HeadersFilter.java": "package app;\n\npublic class HeadersFilter implements Filter {\n" +
			"    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) throws IOException, ServletException {\n" +
			"        ((HttpServletResponse) res).setHeader(\"X-Frame-Options\", \"ALLOWALL\");\n        chain.doFilter(req, res);\n    }\n}\n",
	}
	deploy := map[string]string{"WebContent/WEB-INF/web.xml": "<web-app>\n  <filter>\n    <filter-class>app.HeadersFilter</filter-class>\n  </filter>\n</web-app>\n"}
	trace := traceOf(t, files, nil, deploy, "src/app/HeadersFilter.java", 5)
	if !trace.EntryPoint || len(trace.Gaps) != 0 {
		t.Fatalf("filter not traced to web.xml: %+v", trace)
	}
	requireStep(t, trace, "framework_callback", "doFilter")
	requireStep(t, trace, "registration", "app.HeadersFilter")
}

// Code nothing calls still ships; the trace reports a gap, not a verdict.
func TestDeploymentTraceUncalledFunctionIsAGap(t *testing.T) {
	files := map[string]string{
		"util/sign.go":  "package util\n\nfunc sign(data []byte) []byte {\n\tkey := []byte(\"hardcoded-secret\")\n\treturn hmac.New(sha256.New, key).Sum(data)\n}\n",
		"util/other.go": "package util\n\nfunc Other() {}\n",
	}
	trace := traceOf(t, files, nil, nil, "util/sign.go", 4)
	if trace.EntryPoint || !slices.Contains(trace.Gaps, "no_callers_found") || !slices.Contains(trace.Gaps, "entry_point_not_found") {
		t.Fatalf("uncalled function: %+v", trace)
	}
}

func TestDeploymentTraceBuildConstraintsAndPreprocessorGuards(t *testing.T) {
	files := map[string]string{
		"debug.go": "//go:build debug\n\npackage main\n\nfunc init() {\n\tdumpSecrets()\n}\n",
		"server.c": "#include <stdio.h>\n\nint main(void) {\n#ifdef ENABLE_BACKDOOR\n    system(getenv(\"CMD\"));\n#endif\n    return 0;\n}\n",
	}
	deploy := map[string]string{"Makefile": "CFLAGS += -DENABLE_BACKDOOR\n"}
	goTrace := traceOf(t, files, nil, deploy, "debug.go", 6)
	requireStep(t, goTrace, "build_constraint", "//go:build debug")
	if !goTrace.EntryPoint || !slices.Contains(goTrace.ConfigKeys, "debug") {
		t.Fatalf("build tag trace: %+v", goTrace)
	}
	cTrace := traceOf(t, files, nil, deploy, "server.c", 5)
	requireStep(t, cTrace, "guard", "#ifdef ENABLE_BACKDOOR")
	requireStep(t, cTrace, "config_setting", "-DENABLE_BACKDOOR")
	if !cTrace.EntryPoint {
		t.Fatalf("c trace: %+v", cTrace)
	}
}

func TestDeploymentTraceRespectsBudget(t *testing.T) {
	files := map[string]string{
		"main.go":   "package main\n\nfunc main() {\n\thandle()\n}\n",
		"handle.go": "package main\n\nfunc handle() {\n" + strings.Repeat("\tstep()\n", 200) + "\tsink()\n}\n",
	}
	index := NewEvidenceIndex(files, nil)
	trace := index.DeploymentTrace(SourceRange{Path: "handle.go", Start: 204, End: 204}, nil, 300)
	total := 0
	for _, s := range trace.Steps {
		total += len(s.Text)
	}
	if total > 300 {
		t.Fatalf("trace text %d exceeds budget", total)
	}
	if index.DeploymentTrace(SourceRange{Path: "missing.go", Start: 1}, nil, 300).Gaps[0] != "missing_source" {
		t.Fatal("missing source not reported")
	}
}
