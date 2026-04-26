package supctx

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMain(m *testing.M) {
	// httptest.Server binds to 127.0.0.1 which the SSRF check blocks.
	allowPrivateHosts = true
	os.Exit(m.Run())
}

func TestLoadAll_Inline(t *testing.T) {
	srcs := []Source{
		{Name: "notes", Type: "inline", Location: "admin endpoints are behind mTLS"},
	}
	loaded := LoadAll(context.Background(), srcs, charCounter{})
	if len(loaded) != 1 || loaded[0].Content != "admin endpoints are behind mTLS" {
		t.Fatalf("inline load failed: %+v", loaded)
	}
	if loaded[0].Tokens != len(loaded[0].Content) {
		t.Fatalf("tokens not counted")
	}
}

func TestLoadAll_Path_SingleFile(t *testing.T) {
	tmp := t.TempDir()
	f := filepath.Join(tmp, "spec.yaml")
	if err := os.WriteFile(f, []byte("openapi: 3.0.0"), 0o644); err != nil {
		t.Fatal(err)
	}
	loaded := LoadAll(context.Background(), []Source{
		{Name: "spec", Type: "path", Location: f},
	}, charCounter{})
	if len(loaded) != 1 || !strings.Contains(loaded[0].Content, "openapi: 3.0.0") {
		t.Fatalf("path load failed: %+v", loaded)
	}
	if !strings.Contains(loaded[0].Content, `<file path="spec.yaml">`) {
		t.Fatalf("file envelope missing: %q", loaded[0].Content)
	}
}

func TestLoadAll_Path_Directory(t *testing.T) {
	tmp := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmp, "a.go"), []byte("package a"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmp, "b.go"), []byte("package b"), 0o644); err != nil {
		t.Fatal(err)
	}
	loaded := LoadAll(context.Background(), []Source{
		{Name: "pkg", Type: "path", Location: tmp},
	}, charCounter{})
	if len(loaded) != 1 {
		t.Fatalf("expected 1 loaded source, got %d", len(loaded))
	}
	if !strings.Contains(loaded[0].Content, "package a") || !strings.Contains(loaded[0].Content, "package b") {
		t.Fatalf("directory load missing files: %q", loaded[0].Content)
	}
}

func TestLoadAll_URL(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("threat model content"))
	}))
	defer srv.Close()

	loaded := LoadAll(context.Background(), []Source{
		{Name: "tm", Type: "url", Location: srv.URL},
	}, charCounter{})
	if len(loaded) != 1 || loaded[0].Content != "threat model content" {
		t.Fatalf("url load failed: %+v", loaded)
	}
}

func TestLoadAll_URL_HTMLStrip(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><head><script>evil()</script><style>body{}</style></head><body><h1>Title</h1><p>Content here</p></body></html>`))
	}))
	defer srv.Close()

	loaded := LoadAll(context.Background(), []Source{
		{Name: "wiki", Type: "url", Location: srv.URL},
	}, charCounter{})
	if len(loaded) != 1 {
		t.Fatalf("expected 1 source, got %d", len(loaded))
	}
	c := loaded[0].Content
	if strings.Contains(c, "<script>") || strings.Contains(c, "evil()") {
		t.Fatalf("script not stripped: %q", c)
	}
	if strings.Contains(c, "<h1>") {
		t.Fatalf("tags not stripped: %q", c)
	}
	if !strings.Contains(c, "Title") || !strings.Contains(c, "Content here") {
		t.Fatalf("body text lost: %q", c)
	}
}

func TestLoadAll_URL_RejectsNonHTTP(t *testing.T) {
	loaded := LoadAll(context.Background(), []Source{
		{Name: "bad", Type: "url", Location: "file:///etc/passwd"},
	}, charCounter{})
	if len(loaded) != 0 {
		t.Fatalf("file:// URL should be rejected, got %+v", loaded)
	}
}

func TestLoadAll_SkipsFailures(t *testing.T) {
	loaded := LoadAll(context.Background(), []Source{
		{Name: "ok", Type: "inline", Location: "present"},
		{Name: "bad", Type: "path", Location: "/nonexistent/path/xyz"},
		{Name: "empty", Type: "inline", Location: "   "},
	}, charCounter{})
	if len(loaded) != 1 || loaded[0].Name != "ok" {
		t.Fatalf("expected only 'ok' to survive, got %+v", loaded)
	}
}

func TestLoadAll_UnknownType(t *testing.T) {
	loaded := LoadAll(context.Background(), []Source{
		{Name: "x", Type: "wat", Location: "y"},
	}, charCounter{})
	if len(loaded) != 0 {
		t.Fatalf("unknown type should be skipped")
	}
}
