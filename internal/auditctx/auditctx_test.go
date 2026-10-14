package auditctx

import (
	"fmt"
	"strings"
	"testing"
)

func TestMatchDef(t *testing.T) {
	for _, tc := range []struct {
		line string
		name string
		typ  bool
	}{
		{"func (a *App) PageSearch(w http.ResponseWriter, r *http.Request) {", "PageSearch", false},
		{"func Search[T any](q string) {", "Search", false},
		{"type User struct {", "User", true},
		{"export async function performRedirect () {", "performRedirect", false},
		{"export const isRedirectAllowed = (url: string) => {", "isRedirectAllowed", false},
		{"const sanitize = async function (x) {", "sanitize", false},
		{"exports.hashPassword = function (pw) {", "hashPassword", false},
		{"module.exports = function serveMetrics () {", "serveMetrics", false},
		{"    def load_user(self, user_id):", "load_user", false},
		{"class UserSerializer(serializers.ModelSerializer):", "UserSerializer", true},
		{"  suspend fun findAccount(id: Long): Account {", "findAccount", false},
		{"    public ResponseEntity<User> getUser(@PathVariable Long id) {", "getUser", false},
		{"export interface Basket {", "Basket", true},
		{"export type Role = 'admin' | 'user'", "Role", true},
		{"pub(crate) async fn handle_upload(req: Request) -> Response {", "handle_upload", false},
		{"  validate(input) {", "validate", false},
	} {
		d, ok := matchDef(tc.line)
		if !ok || d.Name != tc.name || d.Type != tc.typ {
			t.Errorf("matchDef(%q) = %+v, %v; want %s type=%v", tc.line, d, ok, tc.name, tc.typ)
		}
	}
	for _, line := range []string{"  if (user) {", "  for (const x of xs) {", "\treturn search(q)", "  } catch (err) {"} {
		if d, ok := matchDef(line); ok {
			t.Errorf("matchDef(%q) = %+v; want no definition", line, d)
		}
	}
}

func goRepo() map[string]string {
	return map[string]string{
		"internal/handlers/pages.go": `package handlers

var searchTmpl *texttmpl.Template

func Load(dir string) {
	searchTmpl, _ = texttmpl.ParseFiles(filepath.Join(dir, "search.html"))
}

func (a *App) PageSearch(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	docs := a.DB.SearchDocuments(q)
	var u models.User
	_ = searchTmpl.Execute(w, map[string]any{"Query": q, "Results": docs, "User": u})
}
`,
		"main.go": `package main

func routes(a *handlers.App) {
	r := chi.NewRouter()
	r.Group(func(r chi.Router) {
		r.Use(auth.RequireAuth)
		r.Get("/search", a.PageSearch)
	})
}
`,
		"internal/db/queries.go": `package db

func (d *DB) SearchDocuments(q string) []Document {
	rows := d.Query("SELECT * FROM docs WHERE title LIKE '%" + q + "%'")
	return scan(rows)
}

func scan(rows *Rows) []Document { return nil }
`,
		"internal/models/models.go": `package models

type User struct {
	ID   int64
	Role string ` + "`json:\"role\"`" + `
}
`,
		"web/templates/search.html": "<h1>Results for {{.Query}}</h1>\n",
	}
}

func TestRetrieveFindsCallersTemplatesAndDefinitions(t *testing.T) {
	ix := NewIndex(goRepo())
	got := ix.Retrieve(Claim{File: "internal/handlers/pages.go", Start: 13, End: 13}, map[string]bool{"internal/handlers/pages.go": true})
	want := []string{
		"main.go:1-10 reference to PageSearch",
		"web/templates/search.html:1-2 template search.html",
		"internal/db/queries.go:3-7 definition of SearchDocuments",
		"internal/models/models.go:3-7 type User",
	}
	var have []string
	for _, e := range got {
		have = append(have, fmt.Sprintf("%s:%d-%d %s", e.File, e.Start, e.End, e.Reason))
	}
	if strings.Join(have, "\n") != strings.Join(want, "\n") {
		t.Fatalf("Retrieve =\n%s\nwant\n%s", strings.Join(have, "\n"), strings.Join(want, "\n"))
	}

	skipped := ix.Retrieve(Claim{File: "internal/handlers/pages.go", Start: 13, End: 13}, map[string]bool{"main.go": true, "web/templates/search.html": true})
	for _, e := range skipped {
		if e.File == "main.go" || e.File == "web/templates/search.html" {
			t.Errorf("retrieved a file already sent: %+v", e)
		}
	}
}

func TestRetrieveSkipsCommonNames(t *testing.T) {
	files := map[string]string{"a.go": "package a\n\nfunc handler() {\n\tsink()\n}\n"}
	for i := 0; i < maxCallerSpan+1; i++ {
		files[fmt.Sprintf("u%d.go", i)] = "package u\n\nvar _ = handler\nvar _ = Sink2\n"
	}
	files["a.go"] = "package a\n\nfunc handler() {\n\tSink2()\n}\n"
	files["b.go"] = "package b\n\nfunc Sink2() {}\n"
	ix := NewIndex(files)
	for _, e := range ix.Retrieve(Claim{File: "a.go", Start: 4}, nil) {
		if strings.HasPrefix(e.Reason, "reference to") {
			t.Errorf("generic caller retrieved: %+v", e)
		}
	}
	// Sink2 is referenced from too many files to retrieve its callers, but
	// its single definition is still retrieved as a callee.
	files["a.go"] = "package a\n\nfunc Caller() {\n\tSink2()\n}\n"
	ix = NewIndex(files)
	got := ix.Retrieve(Claim{File: "a.go", Start: 4}, nil)
	if len(got) != 1 || got[0].Reason != "definition of Sink2" {
		t.Errorf("Retrieve = %+v", got)
	}
}

func TestRenderMergesRangesWithinBudget(t *testing.T) {
	ix := NewIndex(map[string]string{"a.go": "l1\nl2\nl3\nl4\nl5\nl6\nl7\nl8\nl9\n", "b.go": strings.Repeat("x\n", 50)})
	count := func(s string) int { return len(s) }
	out, kept := Render(ix, []Excerpt{
		{File: "a.go", Start: 2, End: 3},
		{File: "a.go", Start: 3, End: 4},
		{File: "a.go", Start: 7, End: 8},
		{File: "a.go", Start: 2, End: 2}, // already covered
		{File: "b.go", Start: 1, End: 50},
	}, 60, count)
	want := "<file path=\"a.go\" lines=\"2-4,7-8\">\n2| l2\n3| l3\n4| l4\n...\n7| l7\n8| l8\n</file>\n\n"
	if out != want || kept != 3 {
		t.Fatalf("Render = %q (kept %d); want %q", out, kept, want)
	}
}
