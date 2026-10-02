package ingest

import "testing"

func TestOptionalDependencyGraph(t *testing.T) {
	files := []SourceFile{
		{Path: "go.mod", Content: "module example.test/app\n"},
		{Path: "main.go", Content: "package main\nimport \"example.test/app/auth\"\n"},
		{Path: "auth/check.go", Content: "package auth\n"},
		{Path: "auth/roles.go", Content: "package auth\n"},
		{Path: "worker.py", Content: "from helpers import run\n"},
		{Path: "helpers.py", Content: "def run(): pass\n"},
	}
	graph := ResolveDependencies(files)
	if len(graph["main.go"]) != 2 || len(graph["auth/check.go"]) != 1 || len(graph["worker.py"]) != 1 {
		t.Fatalf("missing dependency edges: %+v", graph)
	}
	if len(ResolveImports(files)) != 0 {
		t.Fatal("optional changes altered existing resolver")
	}
	graph = ResolveDependencies(files[:2])
	if len(graph) != 0 {
		t.Fatal("included paths outside scan")
	}
}
