package sourceindex

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestSnapshotDeterminismAndFallback(t *testing.T) {
	files := map[string]string{
		"broken.go":      "package app\nfunc Load(value string) {\n",
		"plugin.unknown": "custom source that no parser understands\n",
		"app.kt":         "package app\nclass App(val value: String)\n",
	}
	a := New(files)
	b := New(map[string]string{"app.kt": files["app.kt"], "plugin.unknown": files["plugin.unknown"], "broken.go": files["broken.go"]})
	if !reflect.DeepEqual(a.Snapshot(), b.Snapshot()) {
		t.Fatal("map order changed snapshot identity")
	}
	if a.Mode("broken.go") != "fallback" || a.Mode("plugin.unknown") != "lexical" {
		t.Fatalf("missing extraction status: %+v", a.Snapshot())
	}
	if content, ok := a.Content("plugin.unknown"); !ok || content != files["plugin.unknown"] {
		t.Fatal("unknown language source was dropped")
	}
	files["broken.go"] += "}\n"
	if a.Snapshot().SourceFingerprint == New(files).Snapshot().SourceFingerprint {
		t.Fatal("source edit did not change identity")
	}
	if a.Mode("broken.go") != "fallback" {
		t.Fatal("snapshot observed later map mutation")
	}
}

func TestLocalImportsAcrossLanguages(t *testing.T) {
	files := map[string]string{
		"go.mod":              "module example.test/app\n",
		"cmd/main.go":         "package main\nimport (\"example.test/app/internal/store\"; \"external.test/internal/store\")\nfunc main() {}",
		"internal/store/a.go": "package store\nfunc Load() {}",
		"internal/store/b.go": "package store\nfunc Save() {}",
		"web/main.ts":         "import './helper'; import './missing'; import '../vendor/helper'; import React from 'react'",
		"web/helper.ts":       "export function check() {}",
		"vendor/helper.ts":    "export function check() {}",
		"pkg/app.py":          "from . import helper\nfrom local.models import User\n",
		"pkg/helper.py":       "def check(): pass",
		"local/models.py":     "class User: pass",
		"jvm/App.kt":          "package app\nimport shared.Policy as Guard\nfun check() = Guard()",
		"jvm/Policy.kt":       "package shared\nclass Policy\n",
		"native/app.c":        "#include \"local.h\"\n#include <stdio.h>\n",
		"native/local.h":      "void check(void);",
	}
	ix := New(files)
	want := map[string][]string{
		"cmd/main.go":  {"internal/store/a.go", "internal/store/b.go"},
		"web/main.ts":  {"web/helper.ts"},
		"pkg/app.py":   {"local/models.py", "pkg/helper.py"},
		"jvm/App.kt":   {"jvm/Policy.kt"},
		"native/app.c": {"native/local.h"},
	}
	if got := ix.ImportGraph(); !reflect.DeepEqual(got, want) {
		t.Fatalf("local graph = %#v, want %#v", got, want)
	}
	states := map[string]string{}
	for _, imp := range ix.Imports() {
		states[imp.File+":"+imp.Specifier] = imp.Status
	}
	for key, want := range map[string]string{"web/main.ts:./missing": "unresolved", "web/main.ts:../vendor/helper": "skipped", "web/main.ts:react": "skipped", "cmd/main.go:external.test/internal/store": "skipped"} {
		if states[key] != want {
			t.Errorf("%s status=%q, want %q", key, states[key], want)
		}
	}
}

func TestAmbiguousImportsRemainUnresolved(t *testing.T) {
	ix := New(map[string]string{
		"app.ts":       "import './ambiguous'",
		"ambiguous.ts": "export const value = 1",
		"ambiguous.js": "exports.value = 2",
		"a.kt":         "import p.Guard\nimport external.*\nfun call() = Guard()",
		"one.kt":       "package p\nclass Guard",
		"two.kt":       "package p\nclass Guard",
	})
	if len(ix.ImportGraph()) != 0 {
		t.Fatalf("ambiguous imports selected targets: %v", ix.ImportGraph())
	}
	if ix.Snapshot().Imports["ambiguous"] != 2 {
		t.Fatalf("ambiguities not recorded: %+v", ix.Imports())
	}
	if ix.Snapshot().Imports["skipped"] != 1 {
		t.Fatal("wildcard import was not accounted for")
	}
}

func TestIncompleteGoImportsNeedNoBuild(t *testing.T) {
	ix := New(map[string]string{"partial/main.go": "package main\nimport \"repo/lib\"\nfunc broken(\n", "lib/helper.go": "package lib\nfunc Help() {}"})
	if got := ix.ImportGraph()["partial/main.go"]; !reflect.DeepEqual(got, []string{"lib/helper.go"}) {
		t.Fatalf("incomplete source lost local import: %v", got)
	}
}

func TestNestedGoModulesKeepTheirOwnImportPaths(t *testing.T) {
	ix := New(map[string]string{
		"go.mod":       "module example.test/root",
		"main.go":      "package main\nimport (\"example.test/root/child\"; alias \"example.test/child\")\n",
		"child/go.mod": "module example.test/child",
		"child/a.go":   "package child\nfunc A() {}",
		"child/b.go":   "package child\nfunc B() {}",
	})
	for _, imp := range ix.Imports() {
		if imp.Specifier == "example.test/root/child" && imp.Status != "unresolved" {
			t.Fatalf("nested module leaked into parent: %+v", imp)
		}
		if imp.Specifier == "example.test/child" && (imp.Status != "resolved" || len(imp.Targets) != 2) {
			t.Fatalf("nested module did not resolve: %+v", imp)
		}
	}
}

func TestFeatureSamplesReuseLocalFacts(t *testing.T) {
	ix := New(map[string]string{
		"main.ts":       "import './lib/helper'\nconsole.log('start')",
		"lib/helper.ts": "export function localHelper() {}",
		"feature.rs":    "pub fn unrelated_language_entry() {}",
	})
	samples := ix.FeatureSamples(2000)
	for _, name := range []string{"main.ts", "lib/helper.ts", "feature.rs"} {
		if strings.Count(samples, `path="`+name+`"`) != 1 {
			t.Errorf("sample %s missing or duplicated: %s", name, samples)
		}
	}
	if len(ix.FeatureSamples(50)) > 200 {
		t.Fatal("sample budget exceeded")
	}
}

func BenchmarkIndex(b *testing.B) {
	files := map[string]string{"go.mod": "module bench.test/app"}
	for i := 0; i < 300; i++ {
		files[fmt.Sprintf("service/%03d/handler.go", i)] = fmt.Sprintf("package service\nimport \"bench.test/app/shared\"\nfunc Handle%d(value string) { shared.Check(value) }\n", i)
		files[fmt.Sprintf("web/%03d/handler.ts", i)] = "import '../../shared/policy';\nexport function handle(value: string) { return check(value) }\n"
	}
	files["shared/check.go"] = "package shared\nfunc Check(value string) {}"
	files["web/shared/policy.ts"] = "export function check(value: string) { return value }"
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		New(files)
	}
}
