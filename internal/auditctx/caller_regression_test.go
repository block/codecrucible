package auditctx

import (
	"strings"
	"testing"
)

func TestRetrieveCallerIncludesMountedMiddleware(t *testing.T) {
	files := map[string]string{
		"handlers.ts": "export function listRecords() {\n return (req, res) => res.json(load(req.body.owner));\n}\n",
		"router.ts":   "import { listRecords } from './handlers';\nimport { bindOwner } from './identity';\n" + strings.Repeat("// routing configuration\n", 20) + "router.get('/records', bindOwner(), listRecords());\n",
		"identity.ts": "export function bindOwner() {\n return (req, res, next) => {\n  req.body.owner = req.auth.id;\n  next();\n };\n}\n",
	}
	got := retrievedText(files, "handlers.ts", 2)
	for _, want := range []string{"router.get('/records'", "req.body.owner = req.auth.id"} {
		if !strings.Contains(got, want) {
			t.Fatalf("caller context missing %q: %s", want, got)
		}
	}
}

func TestRetrieveGoCallerIncludesWrapper(t *testing.T) {
	files := map[string]string{
		"handler.go":  "package app\nfunc readRecords(w Writer, r Request) {\n write(w, load(r.Owner))\n}\n",
		"router.go":   "package app\nfunc routes(m Mux) {\n m.Handle(\"/records\", bindOwner(readRecords))\n}\n",
		"identity.go": "package app\nfunc bindOwner(next Handler) Handler {\n return func(w Writer, r Request) { r.Owner = r.Principal; next(w, r) }\n}\n",
	}
	if got := retrievedText(files, "handler.go", 3); !strings.Contains(got, "r.Owner = r.Principal") {
		t.Fatalf("Go caller wrapper missing: %s", got)
	}
}

func TestRetrieveCallerIncludesBareMiddlewareReference(t *testing.T) {
	files := map[string]string{
		"handlers.ts": "export function listRecords(req, res) {\n return res.json(load(req.body.owner));\n}\n",
		"router.ts":   "import { listRecords } from './handlers';\nimport { bindOwner } from './identity';\nrouter.get('/records', bindOwner, listRecords);\n",
		"identity.ts": "export function bindOwner(req, res, next) {\n req.body.owner = req.auth.id;\n next();\n}\n",
	}
	if got := retrievedText(files, "handlers.ts", 2); !strings.Contains(got, "req.body.owner = req.auth.id") {
		t.Fatalf("bare middleware reference missing: %s", got)
	}
}

func TestCallerContextReportsOmissions(t *testing.T) {
	files := map[string]string{
		"handlers.ts": "export function listRecords(req, res) {\n return res.json(req.body);\n}\n",
		"router.ts":   "import { externalGuard } from 'external-library';\nrouter.get('/records', externalGuard, bindOwner, listRecords);\n",
		"one.ts":      "export function bindOwner() { return 1; }",
		"two.ts":      "export function bindOwner() { return 2; }",
	}
	got := retrievedText(files, "handlers.ts", 2)
	for _, want := range []string{"ambiguous caller reference bindOwner", "unresolved or external caller reference externalGuard"} {
		if !strings.Contains(got, want) {
			t.Fatalf("missing %q: %s", want, got)
		}
	}
	ix := NewIndex(files)
	got, _ = Render(ix, ix.Retrieve(Claim{File: "handlers.ts", Start: 2, End: 2}, nil), 1, func(s string) int { return len(s) })
	if !strings.Contains(got, "token budget exhausted") {
		t.Fatal(got)
	}
}

func TestCallerDefinitionsExcludeNeighbouringRegistration(t *testing.T) {
	for _, separator := range []string{"\n", "; "} {
		files := map[string]string{
			"handler.ts": "export function profileHandler(req,res) {\n return res.json(req.body);\n}\n",
			"router.ts":  "router.get('/admin', requireAdmin, adminHandler)" + separator + "router.get('/profile', profileHandler);\n",
			"guards.ts":  "export function requireAdmin(req,res,next) {\n if (!req.admin) throw new Error('ADMIN_ONLY');\n next();\n}\n",
		}
		if got := retrievedText(files, "handler.ts", 2); strings.Contains(got, "ADMIN_ONLY") {
			t.Fatal(got)
		}
	}
}

func TestCallerExternalImportDoesNotResolveLocalNamesake(t *testing.T) {
	files := map[string]string{
		"handler.ts": "export function profileHandler(req,res) {\n return res.json(req.body);\n}\n",
		"router.ts":  "import { bindOwner } from 'auth-lib';\nrouter.get(\n '/profile',\n bindOwner,\n profileHandler\n);\n",
		"local.ts":   "export function bindOwner() { return 'LOCAL_UNRELATED_GUARD'; }\n",
	}
	got := retrievedText(files, "handler.ts", 2)
	if strings.Contains(got, "LOCAL_UNRELATED_GUARD") || !strings.Contains(got, "unresolved or external caller reference bindOwner") {
		t.Fatal(got)
	}
}

func TestCallerImportPathBoundaries(t *testing.T) {
	for _, tc := range []struct {
		module, file string
		want         bool
	}{
		{"@/identity", "src/identity.ts", true},
		{"@/identity", "src/identity/index.ts", true},
		{"~/identity", "src/identity.ts", true},
		{"src/identity", "src/identity.ts", true},
		{"auth-lib", "src/auth.ts", false},
		{"lib", "src/mylib.ts", false},
	} {
		t.Run(tc.module, func(t *testing.T) {
			files := map[string]string{
				"handler.ts": "export function profileHandler(req,res) {\n return res.json(req.body);\n}\n",
				"router.ts":  "import { bindOwner } from '" + tc.module + "';\nrouter.get('/profile', bindOwner, profileHandler);\n",
				tc.file:      "export function bindOwner() { return 'BOUND_GUARD'; }\n",
			}
			got := retrievedText(files, "handler.ts", 2)
			if strings.Contains(got, "BOUND_GUARD") != tc.want {
				t.Fatal(got)
			}
			if !tc.want && !strings.Contains(got, "unresolved or external caller reference bindOwner") {
				t.Fatal(got)
			}
		})
	}
}

func TestCallerGoQualifiedReferencesDoNotProduceOmissions(t *testing.T) {
	files := map[string]string{
		"handler.go":  "package app\nfunc readRecords(w Writer, r Request) {\n write(w, load(r.Owner))\n}\n",
		"router.go":   "package app\nimport \"net/http\"\nfunc routes(m Mux) {\n m.Handle(\"/records\", http.HandlerFunc(bindOwner(readRecords)))\n}\n",
		"identity.go": "package app\nfunc bindOwner(next Handler) Handler {\n return func(w Writer, r Request) { r.Owner = r.Principal; next(w, r) }\n}\n",
	}
	got := retrievedText(files, "handler.go", 3)
	if !strings.Contains(got, "r.Owner = r.Principal") || strings.Contains(got, "caller reference Handle") || strings.Contains(got, "caller reference HandlerFunc") {
		t.Fatal(got)
	}
}

func TestCallerFinalUnicodeStatement(t *testing.T) {
	code := "router.get(profileHandler)é"
	spans := callerStatementSpans(code, "profileHandler")
	if len(spans) != 1 || spans[0][1] != len(code) {
		t.Fatalf("lost final statement: %v", spans)
	}
}

func TestRenderDeduplicatesOmissionNotes(t *testing.T) {
	note := "Audit context omitted: ambiguous caller reference bindOwner"
	got, _ := Render(NewIndex(nil), []Excerpt{{Reason: note}, {Reason: note}}, 100, func(s string) int { return len(s) })
	if strings.Count(got, note) != 1 {
		t.Fatal(got)
	}
}

func TestCallerExternalGoWrapperIsNoted(t *testing.T) {
	files := map[string]string{
		"handler.go": "package app\nfunc readRecords(w Writer, r Request) {\n write(w, load(r.Owner))\n}\n",
		"router.go":  "package app\nimport \"github.com/acme/authz\"\nfunc routes(m Mux) {\n m.Handle(\"/records\", authz.RequireAdmin(readRecords))\n}\n",
	}
	got := retrievedText(files, "handler.go", 3)
	if !strings.Contains(got, "caller reference RequireAdmin") || strings.Contains(got, "caller reference Handle") {
		t.Fatal(got)
	}
}
