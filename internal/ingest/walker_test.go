package ingest

import (
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
)

// writeFile is a test helper that creates a file with the given content in dir.
func writeFile(t *testing.T, dir, name, content string) {
	t.Helper()
	full := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func filePaths(files []SourceFile) []string {
	out := make([]string, len(files))
	for i, f := range files {
		out[i] = f.Path
	}
	sort.Strings(out)
	return out
}

func TestWalkDir_SimpleDirectory(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "main.go", "package main\n")
	writeFile(t, root, "lib/utils.go", "package lib\n")
	writeFile(t, root, "lib/helpers.py", "def helper(): pass\n")

	files, err := WalkDir(root)
	if err != nil {
		t.Fatalf("WalkDir: %v", err)
	}

	paths := filePaths(files)
	expected := []string{"lib/helpers.py", "lib/utils.go", "main.go"}
	if len(paths) != len(expected) {
		t.Fatalf("got %d files %v, want %d files %v", len(paths), paths, len(expected), expected)
	}
	for i, p := range paths {
		if p != expected[i] {
			t.Errorf("file %d: got %q, want %q", i, p, expected[i])
		}
	}
}

func TestWalkDir_GitignoreRespected(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, ".gitignore", "*.log\nbuild/\n")
	writeFile(t, root, "main.go", "package main\n")
	writeFile(t, root, "app.log", "some log\n")
	writeFile(t, root, "build/output.go", "package build\n")

	files, err := WalkDir(root)
	if err != nil {
		t.Fatalf("WalkDir: %v", err)
	}

	paths := filePaths(files)
	if len(paths) != 1 {
		t.Fatalf("got %v, want only [main.go]", paths)
	}
	if paths[0] != "main.go" {
		t.Errorf("got %q, want %q", paths[0], "main.go")
	}
}

func TestWalkDir_NestedGitignoreOverrides(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, ".gitignore", "*.tmp\n")
	writeFile(t, root, "main.go", "package main\n")
	writeFile(t, root, "cache.tmp", "cached\n")
	// Nested .gitignore adds its own pattern.
	writeFile(t, root, "sub/.gitignore", "*.dat\n")
	writeFile(t, root, "sub/code.go", "package sub\n")
	writeFile(t, root, "sub/data.dat", "binary data\n")
	writeFile(t, root, "sub/notes.tmp", "temp notes\n")

	files, err := WalkDir(root)
	if err != nil {
		t.Fatalf("WalkDir: %v", err)
	}

	paths := filePaths(files)
	// cache.tmp ignored by root .gitignore
	// sub/data.dat ignored by sub/.gitignore
	// sub/notes.tmp ignored by root .gitignore
	expected := []string{"main.go", "sub/code.go"}
	if len(paths) != len(expected) {
		t.Fatalf("got %v, want %v", paths, expected)
	}
	for i, p := range paths {
		if p != expected[i] {
			t.Errorf("file %d: got %q, want %q", i, p, expected[i])
		}
	}
}

func TestWalkDir_SymlinksSkipped(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink test not reliable on windows")
	}

	root := t.TempDir()
	writeFile(t, root, "real.go", "package main\n")

	// Create a file symlink.
	target := filepath.Join(root, "real.go")
	link := filepath.Join(root, "link.go")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}

	// Create a directory symlink.
	subdir := filepath.Join(root, "subdir")
	if err := os.Mkdir(subdir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, root, "subdir/inner.go", "package subdir\n")
	dirLink := filepath.Join(root, "linkeddir")
	if err := os.Symlink(subdir, dirLink); err != nil {
		t.Fatal(err)
	}

	files, err := WalkDir(root)
	if err != nil {
		t.Fatalf("WalkDir: %v", err)
	}

	paths := filePaths(files)
	// Only real.go and subdir/inner.go should appear.
	// link.go and linkeddir/* should be skipped.
	expected := []string{"real.go", "subdir/inner.go"}
	if len(paths) != len(expected) {
		t.Fatalf("got %v, want %v", paths, expected)
	}
	for i, p := range paths {
		if p != expected[i] {
			t.Errorf("file %d: got %q, want %q", i, p, expected[i])
		}
	}
}

func TestWalkDir_BinaryFileDetection(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "source.go", "package main\n")

	// Write a binary file with null byte in first 512 bytes.
	binaryContent := make([]byte, 256)
	binaryContent[0] = 0x89
	binaryContent[1] = 0x50  // PNG-like header
	binaryContent[10] = 0x00 // null byte
	if err := os.WriteFile(filepath.Join(root, "image.png"), binaryContent, 0o644); err != nil {
		t.Fatal(err)
	}

	// Write a text file that happens to be large but has no null bytes.
	bigText := strings.Repeat("hello world\n", 1000)
	writeFile(t, root, "large.txt", bigText)

	files, err := WalkDir(root)
	if err != nil {
		t.Fatalf("WalkDir: %v", err)
	}

	paths := filePaths(files)
	// image.png should be excluded (binary), source.go and large.txt included.
	expected := []string{"large.txt", "source.go"}
	if len(paths) != len(expected) {
		t.Fatalf("got %v, want %v", paths, expected)
	}
}

func TestWalkDir_EmptyDirectories(t *testing.T) {
	root := t.TempDir()
	// Create empty subdirectories.
	if err := os.MkdirAll(filepath.Join(root, "empty1"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "empty2", "nested"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, root, "file.go", "package main\n")

	files, err := WalkDir(root)
	if err != nil {
		t.Fatalf("WalkDir: %v", err)
	}

	paths := filePaths(files)
	if len(paths) != 1 || paths[0] != "file.go" {
		t.Fatalf("got %v, want [file.go]", paths)
	}
}

func TestWalkDir_DeeplyNested(t *testing.T) {
	root := t.TempDir()

	// Create a directory structure 12 levels deep.
	deepPath := "a/b/c/d/e/f/g/h/i/j/k/l"
	writeFile(t, root, filepath.Join(deepPath, "deep.go"), "package deep\n")

	files, err := WalkDir(root)
	if err != nil {
		t.Fatalf("WalkDir: %v", err)
	}

	if len(files) != 1 {
		t.Fatalf("got %d files, want 1", len(files))
	}
	if files[0].Path != filepath.Join(deepPath, "deep.go") {
		t.Errorf("got path %q, want %q", files[0].Path, filepath.Join(deepPath, "deep.go"))
	}
}

func TestWalkDir_PermissionDenied(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("permission test not reliable on windows")
	}
	if os.Getuid() == 0 {
		t.Skip("running as root, permission test not meaningful")
	}

	root := t.TempDir()
	writeFile(t, root, "readable.go", "package main\n")

	// Create an unreadable directory.
	unreadable := filepath.Join(root, "secret")
	if err := os.MkdirAll(unreadable, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, root, "secret/hidden.go", "package secret\n")
	if err := os.Chmod(unreadable, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chmod(unreadable, 0o755); err != nil {
			t.Fatalf("restoring unreadable dir permissions: %v", err)
		}
	})

	files, err := WalkDir(root)
	if err != nil {
		t.Fatalf("WalkDir should not fail on permission errors: %v", err)
	}

	paths := filePaths(files)
	// readable.go should still be returned; the walk should continue.
	if len(paths) != 1 || paths[0] != "readable.go" {
		t.Fatalf("got %v, want [readable.go]", paths)
	}
}

func TestWalkDir_MixedEncodings(t *testing.T) {
	root := t.TempDir()

	// Valid UTF-8.
	writeFile(t, root, "utf8.go", "// café résumé\npackage main\n")

	// Latin-1 bytes (not valid UTF-8): 0xE9 is 'é' in Latin-1 but invalid standalone UTF-8.
	latin1Content := []byte("// caf\xe9\npackage main\n")
	if err := os.WriteFile(filepath.Join(root, "latin1.go"), latin1Content, 0o644); err != nil {
		t.Fatal(err)
	}

	files, err := WalkDir(root)
	if err != nil {
		t.Fatalf("WalkDir: %v", err)
	}

	if len(files) != 2 {
		t.Fatalf("got %d files, want 2", len(files))
	}

	// Both files should have content (no panic, no error).
	for _, f := range files {
		if f.Content == "" {
			t.Errorf("file %q has empty content", f.Path)
		}
		if f.LineCount == 0 {
			t.Errorf("file %q has 0 lines", f.Path)
		}
	}

	// The Latin-1 file should have replacement characters for invalid bytes.
	for _, f := range files {
		if f.Path == "latin1.go" {
			if !strings.Contains(f.Content, "\uFFFD") {
				t.Error("expected replacement character in latin1.go content")
			}
		}
	}
}

func TestInferLanguage(t *testing.T) {
	tests := []struct {
		path string
		want string
	}{
		{"main.go", "go"},
		{"script.py", "python"},
		{"app.ts", "typescript"},
		{"component.tsx", "typescript"},
		{"index.js", "javascript"},
		{"App.jsx", "javascript"},
		{"Service.java", "java"},
		{"helper.rb", "ruby"},
		{"lib.rs", "rust"},
		{"code.c", "c"},
		{"code.cpp", "cpp"},
		{"code.cs", "csharp"},
		{"app.swift", "swift"},
		{"app.kt", "kotlin"},
		{"test.scala", "scala"},
		{"page.php", "php"},
		{"run.sh", "shell"},
		{"config.yaml", "yaml"},
		{"config.yml", "yaml"},
		{"data.json", "json"},
		{"layout.html", "html"},
		{"style.css", "css"},
		{"query.sql", "sql"},
		{"schema.proto", "protobuf"},
		{"Dockerfile", "dockerfile"},
		{"Dockerfile.prod", "dockerfile"},
		{"Makefile", "makefile"},
		{"unknown.xyz", ""},
		{"noext", ""},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got := InferLanguage(tt.path)
			if got != tt.want {
				t.Errorf("InferLanguage(%q) = %q, want %q", tt.path, got, tt.want)
			}
		})
	}
}

func TestWalkDir_SourceFileMetadata(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "main.go", "package main\n\nfunc main() {}\n")

	files, err := WalkDir(root)
	if err != nil {
		t.Fatalf("WalkDir: %v", err)
	}

	if len(files) != 1 {
		t.Fatalf("got %d files, want 1", len(files))
	}

	f := files[0]
	if f.Path != "main.go" {
		t.Errorf("Path = %q, want %q", f.Path, "main.go")
	}
	if f.Content != "package main\n\nfunc main() {}\n" {
		t.Errorf("Content = %q, want %q", f.Content, "package main\n\nfunc main() {}\n")
	}
	if f.LineCount != 3 {
		t.Errorf("LineCount = %d, want 3", f.LineCount)
	}
	if f.Language != "go" {
		t.Errorf("Language = %q, want %q", f.Language, "go")
	}
}

func TestWalkDir_GitDirectorySkipped(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "main.go", "package main\n")
	writeFile(t, root, ".git/objects/pack", "binary pack\n")
	writeFile(t, root, ".git/HEAD", "ref: refs/heads/main\n")

	files, err := WalkDir(root)
	if err != nil {
		t.Fatalf("WalkDir: %v", err)
	}

	paths := filePaths(files)
	if len(paths) != 1 || paths[0] != "main.go" {
		t.Fatalf("got %v, want [main.go]", paths)
	}
}

func TestIsBinaryContent(t *testing.T) {
	tests := []struct {
		name   string
		data   []byte
		binary bool
	}{
		{"empty", []byte{}, false},
		{"text", []byte("hello world\n"), false},
		{"null at start", []byte{0x00, 0x41, 0x42}, true},
		{"null in middle", append([]byte("hello"), append([]byte{0x00}, []byte("world")...)...), true},
		{"null at byte 511", func() []byte {
			b := make([]byte, 512)
			for i := range b {
				b[i] = 'A'
			}
			b[511] = 0x00
			return b
		}(), true},
		{"null at byte 512", func() []byte {
			b := make([]byte, 513)
			for i := range b {
				b[i] = 'A'
			}
			b[512] = 0x00
			return b
		}(), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isBinaryContent(tt.data)
			if got != tt.binary {
				t.Errorf("isBinaryContent = %v, want %v", got, tt.binary)
			}
		})
	}
}

func TestCountLines(t *testing.T) {
	tests := []struct {
		input string
		want  int
	}{
		{"", 0},
		{"a", 1},
		{"a\n", 1},
		{"a\nb\n", 2},
		{"a\nb", 2},
		{"a\nb\nc\n", 3},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := countLines(tt.input)
			if got != tt.want {
				t.Errorf("countLines(%q) = %d, want %d", tt.input, got, tt.want)
			}
		})
	}
}

func TestSanitizeUTF8(t *testing.T) {
	// Valid UTF-8 passes through unchanged.
	valid := "hello café"
	if got := sanitizeUTF8([]byte(valid)); got != valid {
		t.Errorf("sanitizeUTF8 changed valid UTF-8: got %q", got)
	}

	// Invalid bytes get replaced with U+FFFD.
	invalid := []byte("caf\xe9 world")
	got := sanitizeUTF8(invalid)
	if !strings.Contains(got, "\uFFFD") {
		t.Errorf("expected replacement character, got %q", got)
	}
	if !strings.Contains(got, "caf") || !strings.Contains(got, " world") {
		t.Errorf("valid parts should be preserved, got %q", got)
	}
}

func TestWalkDir_GitignoreDirectoryPattern(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, ".gitignore", "vendor/\nnode_modules/\n")
	writeFile(t, root, "main.go", "package main\n")
	writeFile(t, root, "vendor/dep.go", "package vendor\n")
	writeFile(t, root, "node_modules/pkg/index.js", "module.exports = {}\n")

	files, err := WalkDir(root)
	if err != nil {
		t.Fatalf("WalkDir: %v", err)
	}

	paths := filePaths(files)
	if len(paths) != 1 || paths[0] != "main.go" {
		t.Fatalf("got %v, want [main.go]", paths)
	}
}

func TestWalkDir_NonexistentRoot(t *testing.T) {
	_, err := WalkDir("/nonexistent/path/that/does/not/exist")
	if err == nil {
		t.Fatal("expected error for nonexistent root, got nil")
	}
}

func TestWalkDir_EmptyRoot(t *testing.T) {
	root := t.TempDir()

	files, err := WalkDir(root)
	if err != nil {
		t.Fatalf("WalkDir: %v", err)
	}

	if len(files) != 0 {
		t.Fatalf("got %d files, want 0", len(files))
	}
}

func TestWalkDir_BinaryAtExactly512Boundary(t *testing.T) {
	root := t.TempDir()

	// Null byte at position 511 (last checked byte) — should be detected as binary.
	data511 := make([]byte, 600)
	for i := range data511 {
		data511[i] = 'A'
	}
	data511[511] = 0x00
	if err := os.WriteFile(filepath.Join(root, "boundary.bin"), data511, 0o644); err != nil {
		t.Fatal(err)
	}

	// Null byte at position 512 (just outside checked range) — should NOT be binary.
	data512 := make([]byte, 600)
	for i := range data512 {
		data512[i] = 'A'
	}
	data512[512] = 0x00
	if err := os.WriteFile(filepath.Join(root, "not_binary.txt"), data512, 0o644); err != nil {
		t.Fatal(err)
	}

	files, err := WalkDir(root)
	if err != nil {
		t.Fatalf("WalkDir: %v", err)
	}

	paths := filePaths(files)
	if len(paths) != 1 || paths[0] != "not_binary.txt" {
		t.Fatalf("got %v, want [not_binary.txt]", paths)
	}
}
