package sourceindex

import (
	"reflect"
	"strings"
	"testing"
)

func TestImportOfAcrossLanguages(t *testing.T) {
	ix := New(map[string]string{
		"web/router.ts":            "import def, { a, b as c } from './lib';\nimport * as ns from '@/util';\nimport {\n  multi\n} from 'pkg';\nconst { d, e: f } = require('./lib');\nconst g = require('pkg');\n",
		"web/lib.ts":               "export function a() {}\n",
		"src/util.ts":              "export function u() {}\n",
		"app/urls.py":              "from .guards import (\n    require_owner,\n    other as alias,\n)\nimport os\nimport json as j\nfrom . import helpers\n",
		"app/guards.py":            "def require_owner(v):\n    return v\n",
		"app/helpers.py":           "def h():\n    pass\n",
		"go.mod":                   "module example.com/m\n",
		"cmd/main.go":              "package main\nimport (\n\tauthz \"example.com/m/authz\"\n\t\"net/http\"\n)\nfunc main() { authz.Check(); http.ListenAndServe() }\n",
		"authz/authz.go":           "package authz\nfunc Check() {}\n",
		"src/pay/Routes.kt":        "package pay\nimport pay.guards.requireOwner\nfun routes() { requireOwner() }\n",
		"src/pay/guards/Guards.kt": "package pay.guards\nfun requireOwner() {}\n",
	})
	for _, tc := range []struct {
		file, name, spec string
		targets          []string
	}{
		{"web/router.ts", "def", "./lib", []string{"web/lib.ts"}},
		{"web/router.ts", "a", "./lib", []string{"web/lib.ts"}},
		{"web/router.ts", "c", "./lib", []string{"web/lib.ts"}},
		{"web/router.ts", "ns", "@/util", []string{"src/util.ts"}},
		{"web/router.ts", "multi", "pkg", nil},
		{"web/router.ts", "d", "./lib", []string{"web/lib.ts"}},
		{"web/router.ts", "f", "./lib", []string{"web/lib.ts"}},
		{"web/router.ts", "g", "pkg", nil},
		{"app/urls.py", "require_owner", ".guards", []string{"app/guards.py"}},
		{"app/urls.py", "alias", ".guards", []string{"app/guards.py"}},
		{"app/urls.py", "os", "os", nil},
		{"app/urls.py", "j", "json", nil},
		{"app/urls.py", "helpers", ".helpers", []string{"app/helpers.py"}},
		{"cmd/main.go", "authz", "example.com/m/authz", []string{"authz/authz.go"}},
		{"cmd/main.go", "http", "net/http", nil},
		{"src/pay/Routes.kt", "requireOwner", "pay.guards.requireOwner", []string{"src/pay/guards/Guards.kt"}},
	} {
		b, ok := ix.ImportOf(tc.file, tc.name)
		if !ok || b.Specifier != tc.spec || !reflect.DeepEqual(b.Targets, tc.targets) {
			t.Errorf("ImportOf(%s, %s) = %+v, %v; want %s %v", tc.file, tc.name, b, ok, tc.spec, tc.targets)
		}
	}
	for _, name := range []string{"b", "e", "other", "Check"} {
		if _, ok := ix.ImportOf("web/router.ts", name); ok {
			t.Errorf("%s is not a local binding", name)
		}
	}
}

func TestStatementsReferencingSkipsImportsAndSplitsRegistrations(t *testing.T) {
	ix := New(map[string]string{
		"router.ts": "import {\n  handler\n} from './h';\nrouter.get('/a', guard, other); router.get(\n  '/b',\n  handler\n);\n",
		"urls.py":   "from .h import (\n    handler,\n)\nroute('/b', handler)\n",
		"Routes.kt": "package p\nimport p.handler\nfun r() {\n    get(\"/b\", handler)\n}\n",
		"final.ts":  "router.get(handler)é",
	})
	for file, want := range map[string][]string{
		"router.ts": {"router.get(\n  '/b',\n  handler\n);"},
		"urls.py":   {"route('/b', handler)"},
		"Routes.kt": {"    get(\"/b\", handler)\n"},
		"final.ts":  {"router.get(handler)é"},
	} {
		content, _ := ix.Content(file)
		var got []string
		for _, span := range ix.StatementsReferencing(file, "handler") {
			got = append(got, strings.TrimLeft(content[span[0]:span[1]], " "))
		}
		for i := range want {
			want[i] = strings.TrimLeft(want[i], " ")
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s: statements %q, want %q", file, got, want)
		}
	}
}

func TestNamesInReportsQualifiersAndLines(t *testing.T) {
	ix := New(map[string]string{"r.ts": "x();\nrouter.get(\n  '/b',\n  authz . require,\n  handler\n);\n"})
	spans := ix.StatementsReferencing("r.ts", "handler")
	if len(spans) != 1 {
		t.Fatal(spans)
	}
	var got []string
	for _, r := range ix.NamesIn("r.ts", spans[0]) {
		got = append(got, r.Qualifier+"."+r.Name+"@"+string(rune('0'+r.Line)))
	}
	want := []string{"router.get@2", "authz.require@4", ".handler@5"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("NamesIn = %q, want %q", got, want)
	}
}

func TestMaskedSourceUsesEachLanguagesComments(t *testing.T) {
	ix := New(map[string]string{
		"a.rb": "guard # hidden_ruby\n",
		"a.py": "guard # hidden_python\n",
		"a.c":  "#include \"visible.h\"\nguard // hidden_c\n",
		"a.ts": "guard // hidden_ts\nconst s = '# visible_hash_in_ts';\n",
	})
	for file, tc := range map[string]struct{ hidden, visible string }{
		"a.rb": {"hidden_ruby", "guard"},
		"a.py": {"hidden_python", "guard"},
		"a.c":  {"hidden_c", "#include"},
		"a.ts": {"hidden_ts", "guard"},
	} {
		code := ix.MaskedSource(file)
		content, _ := ix.Content(file)
		if strings.Contains(code, tc.hidden) || !strings.Contains(code, tc.visible) || len(code) != len(strings.TrimSuffix(content, "\n")) {
			t.Errorf("%s masked as %q", file, code)
		}
	}
}

func TestKnowsArgumentsFollowsAdapterCapability(t *testing.T) {
	ix := New(map[string]string{"a.go": "package a\nfunc f() { g(h) }\n", "b.ts": "f(h)\n", "c.go": "package (\n"})
	if !ix.KnowsArguments("a.go") || ix.KnowsArguments("b.ts") || ix.KnowsArguments("c.go") || ix.KnowsArguments("missing") {
		t.Fatal("argument capability misreported")
	}
}
