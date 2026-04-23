package ingest

import (
	"strings"
	"testing"
)

// makeFile creates a SourceFile with the given path and dummy content.
func makeFile(path string) SourceFile {
	return SourceFile{
		Path:      path,
		Content:   "package main\n",
		LineCount: 1,
		Language:  InferLanguage(path),
	}
}

// makeFileWithContent creates a SourceFile with specific content.
func makeFileWithContent(path, content string) SourceFile {
	return SourceFile{
		Path:      path,
		Content:   content,
		LineCount: countLines(content),
		Language:  InferLanguage(path),
	}
}

func TestFilterFiles_EmptyInput(t *testing.T) {
	kept, stats := FilterFiles(nil, FilterConfig{})
	if len(kept) != 0 {
		t.Errorf("expected empty slice, got %d files", len(kept))
	}
	if stats.Total != 0 {
		t.Errorf("expected total 0, got %d", stats.Total)
	}

	kept, stats = FilterFiles([]SourceFile{}, FilterConfig{})
	if len(kept) != 0 {
		t.Errorf("expected empty slice, got %d files", len(kept))
	}
	if stats.Total != 0 {
		t.Errorf("expected total 0, got %d", stats.Total)
	}
}

func TestFilterFiles_DefaultExclusions_TestFiles(t *testing.T) {
	files := []SourceFile{
		makeFile("main.go"),
		makeFile("handler_test.go"),
		makeFile("test_helper.py"),
		makeFile("component_spec.ts"),
		makeFile("widget_spec.js"),
		makeFile("component_spec.tsx"),
		makeFile("widget_spec.jsx"),
		makeFile("app_test.py"),
		makeFile("app_test.ts"),
		makeFile("app_test.js"),
		makeFile("test_util.go"),
		makeFile("test_util.ts"),
		makeFile("test_util.js"),
	}

	kept, stats := FilterFiles(files, FilterConfig{})

	if len(kept) != 1 {
		paths := make([]string, len(kept))
		for i, f := range kept {
			paths[i] = f.Path
		}
		t.Fatalf("expected 1 file kept, got %d: %v", len(kept), paths)
	}
	if kept[0].Path != "main.go" {
		t.Errorf("expected main.go, got %q", kept[0].Path)
	}
	if stats.Tests != 12 {
		t.Errorf("expected 12 test files excluded, got %d", stats.Tests)
	}
}

func TestFilterFiles_DefaultExclusions_TestDirectories(t *testing.T) {
	files := []SourceFile{
		makeFile("src/main.go"),
		makeFile("test/helper.go"),
		makeFile("tests/integration.py"),
		makeFile("__tests__/component.test.js"),
		makeFile("spec/models/user_spec.rb"),
		makeFile("src/__tests__/deep/nested.js"),
	}

	kept, stats := FilterFiles(files, FilterConfig{})

	if len(kept) != 1 {
		paths := make([]string, len(kept))
		for i, f := range kept {
			paths[i] = f.Path
		}
		t.Fatalf("expected 1 file kept, got %d: %v", len(kept), paths)
	}
	if kept[0].Path != "src/main.go" {
		t.Errorf("expected src/main.go, got %q", kept[0].Path)
	}
	if stats.Tests != 5 {
		t.Errorf("expected 5 test directory files excluded, got %d", stats.Tests)
	}
}

func TestFilterFiles_DefaultExclusions_VendorDirs(t *testing.T) {
	files := []SourceFile{
		makeFile("main.go"),
		makeFile("vendor/github.com/pkg/dep.go"),
		makeFile("node_modules/express/index.js"),
		makeFile("__pycache__/module.cpython-39.py"),
		makeFile(".venv/lib/python3.9/site-packages/pip.py"),
		makeFile("venv/lib/python3.9/site-packages/pip.py"),
	}

	kept, stats := FilterFiles(files, FilterConfig{})

	if len(kept) != 1 {
		t.Fatalf("expected 1 file kept, got %d", len(kept))
	}
	if kept[0].Path != "main.go" {
		t.Errorf("expected main.go, got %q", kept[0].Path)
	}
	if stats.Vendor != 5 {
		t.Errorf("expected 5 vendor files excluded, got %d", stats.Vendor)
	}
}

func TestFilterFiles_DefaultExclusions_BinaryExtensions(t *testing.T) {
	files := []SourceFile{
		makeFile("main.go"),
		makeFile("app.exe"),
		makeFile("lib.dll"),
		makeFile("lib.so"),
		makeFile("lib.dylib"),
		makeFile("image.png"),
		makeFile("photo.jpg"),
		makeFile("icon.gif"),
		makeFile("archive.zip"),
		makeFile("package.tar"),
		makeFile("compressed.gz"),
	}

	kept, stats := FilterFiles(files, FilterConfig{})

	if len(kept) != 1 {
		t.Fatalf("expected 1 file kept, got %d", len(kept))
	}
	if kept[0].Path != "main.go" {
		t.Errorf("expected main.go, got %q", kept[0].Path)
	}
	if stats.Binary != 10 {
		t.Errorf("expected 10 binary files excluded, got %d", stats.Binary)
	}
}

func TestFilterFiles_DefaultExclusions_Docs(t *testing.T) {
	files := []SourceFile{
		makeFile("main.go"),
		makeFile("README.md"),
		makeFile("docs/guide.md"),
		makeFile("CHANGELOG.md"),
	}

	kept, stats := FilterFiles(files, FilterConfig{})

	if len(kept) != 1 {
		t.Fatalf("expected 1 file kept, got %d", len(kept))
	}
	if kept[0].Path != "main.go" {
		t.Errorf("expected main.go, got %q", kept[0].Path)
	}
	if stats.Docs != 3 {
		t.Errorf("expected 3 docs excluded, got %d", stats.Docs)
	}
}

func TestFilterFiles_AlwaysInclude_Proto(t *testing.T) {
	files := []SourceFile{
		makeFile("api/service.proto"),
		makeFile("test/api.proto"),                          // in test dir, but .proto
		makeFile("vendor/google/protobuf/descriptor.proto"), // in vendor dir, but .proto
	}

	kept, _ := FilterFiles(files, FilterConfig{})

	if len(kept) != 3 {
		paths := make([]string, len(kept))
		for i, f := range kept {
			paths[i] = f.Path
		}
		t.Fatalf("expected all 3 .proto files kept, got %d: %v", len(kept), paths)
	}
}

func TestFilterFiles_AlwaysInclude_SQL(t *testing.T) {
	files := []SourceFile{
		makeFile("db/migrations/001.sql"),
		makeFile("test/fixtures.sql"), // in test dir, but .sql
	}

	kept, _ := FilterFiles(files, FilterConfig{})

	if len(kept) != 2 {
		t.Fatalf("expected 2 .sql files kept, got %d", len(kept))
	}
}

func TestFilterFiles_AlwaysInclude_GraphQL(t *testing.T) {
	files := []SourceFile{
		makeFile("schema/types.graphql"),
		makeFile("test/query.graphql"), // in test dir, but .graphql
		makeFile("api/schema.gql"),
	}

	kept, _ := FilterFiles(files, FilterConfig{})

	if len(kept) != 3 {
		t.Fatalf("expected 3 graphql files kept, got %d", len(kept))
	}
}

func TestFilterFiles_IncludeTestsFlag(t *testing.T) {
	files := []SourceFile{
		makeFile("main.go"),
		makeFile("main_test.go"),
		makeFile("test/helper.go"),
		makeFile("__tests__/component.js"),
	}

	kept, stats := FilterFiles(files, FilterConfig{IncludeTests: true})

	if len(kept) != 4 {
		paths := make([]string, len(kept))
		for i, f := range kept {
			paths[i] = f.Path
		}
		t.Fatalf("expected 4 files kept with --include-tests, got %d: %v", len(kept), paths)
	}
	if stats.Tests != 0 {
		t.Errorf("expected 0 test exclusions with --include-tests, got %d", stats.Tests)
	}
}

func TestFilterFiles_IncludeDocsFlag(t *testing.T) {
	files := []SourceFile{
		makeFile("main.go"),
		makeFile("README.md"),
		makeFile("docs/guide.md"),
	}

	kept, stats := FilterFiles(files, FilterConfig{IncludeDocs: true})

	if len(kept) != 3 {
		t.Fatalf("expected 3 files kept with --include-docs, got %d", len(kept))
	}
	if stats.Docs != 0 {
		t.Errorf("expected 0 doc exclusions with --include-docs, got %d", stats.Docs)
	}
}

func TestFilterFiles_CustomIncludeOverridesExclusion(t *testing.T) {
	files := []SourceFile{
		makeFile("main.go"),
		makeFile("main_test.go"),
		makeFile("vendor/important.go"),
	}

	// Custom include pattern should override default exclusions.
	kept, _ := FilterFiles(files, FilterConfig{
		Include: []string{"*_test.go", "vendor/important.go"},
	})

	if len(kept) != 3 {
		paths := make([]string, len(kept))
		for i, f := range kept {
			paths[i] = f.Path
		}
		t.Fatalf("expected 3 files kept with custom include, got %d: %v", len(kept), paths)
	}
}

func TestFilterFiles_CustomExcludeAddsExclusions(t *testing.T) {
	files := []SourceFile{
		makeFile("main.go"),
		makeFile("generated.pb.go"),
		makeFile("config.yaml"),
	}

	kept, stats := FilterFiles(files, FilterConfig{
		Exclude: []string{"*.pb.go", "*.yaml"},
	})

	if len(kept) != 1 {
		paths := make([]string, len(kept))
		for i, f := range kept {
			paths[i] = f.Path
		}
		t.Fatalf("expected 1 file kept, got %d: %v", len(kept), paths)
	}
	if kept[0].Path != "main.go" {
		t.Errorf("expected main.go, got %q", kept[0].Path)
	}
	if stats.Custom != 2 {
		t.Errorf("expected 2 custom exclusions, got %d", stats.Custom)
	}
}

func TestFilterFiles_CustomExcludeDoesNotOverrideAlwaysInclude(t *testing.T) {
	files := []SourceFile{
		makeFile("schema.proto"),
		makeFile("migration.sql"),
		makeFile("types.graphql"),
	}

	// Custom exclude should NOT override always-include extensions.
	kept, _ := FilterFiles(files, FilterConfig{
		Exclude: []string{"*.proto", "*.sql", "*.graphql"},
	})

	if len(kept) != 3 {
		t.Fatalf("expected 3 always-include files kept despite custom exclude, got %d", len(kept))
	}
}

func TestFilterFiles_BinaryContentDetection(t *testing.T) {
	// File with null byte in first 512 bytes.
	binaryContent := strings.Repeat("A", 100) + "\x00" + strings.Repeat("B", 100)
	files := []SourceFile{
		makeFile("main.go"),
		makeFileWithContent("mystery.dat", binaryContent),
	}

	kept, stats := FilterFiles(files, FilterConfig{})

	if len(kept) != 1 {
		t.Fatalf("expected 1 file kept, got %d", len(kept))
	}
	if kept[0].Path != "main.go" {
		t.Errorf("expected main.go, got %q", kept[0].Path)
	}
	if stats.Binary != 1 {
		t.Errorf("expected 1 binary file excluded, got %d", stats.Binary)
	}
}

func TestFilterFiles_BinaryContentBoundary(t *testing.T) {
	// Null byte at exactly position 511 (last checked byte) — binary.
	data511 := strings.Repeat("A", 511) + "\x00" + strings.Repeat("B", 100)
	// Null byte at position 512 (outside check range) — not binary.
	data512 := strings.Repeat("A", 512) + "\x00" + strings.Repeat("B", 100)

	files := []SourceFile{
		makeFileWithContent("binary.dat", data511),
		makeFileWithContent("text.dat", data512),
	}

	kept, stats := FilterFiles(files, FilterConfig{})

	if len(kept) != 1 {
		paths := make([]string, len(kept))
		for i, f := range kept {
			paths[i] = f.Path
		}
		t.Fatalf("expected 1 file kept, got %d: %v", len(kept), paths)
	}
	if kept[0].Path != "text.dat" {
		t.Errorf("expected text.dat, got %q", kept[0].Path)
	}
	if stats.Binary != 1 {
		t.Errorf("expected 1 binary exclusion, got %d", stats.Binary)
	}
}

func TestFilterFiles_EdgeCase_NoExtension(t *testing.T) {
	files := []SourceFile{
		makeFile("Makefile"),
		makeFile("Dockerfile"),
		makeFile("Procfile"),
		makeFile(".env"),
		makeFile(".gitignore"),
		makeFile("LICENSE"),
	}

	kept, _ := FilterFiles(files, FilterConfig{})

	// All of these should pass through — none match binary/test/vendor/docs patterns.
	if len(kept) != 6 {
		paths := make([]string, len(kept))
		for i, f := range kept {
			paths[i] = f.Path
		}
		t.Fatalf("expected 6 files kept, got %d: %v", len(kept), paths)
	}
}

func TestFilterFiles_EdgeCase_DotFiles(t *testing.T) {
	files := []SourceFile{
		makeFile(".env"),
		makeFile(".dockerignore"),
		makeFile(".eslintrc.js"), // low-value: build tooling config
		makeFile(".prettierrc"),  // low-value: build tooling config
	}

	kept, stats := FilterFiles(files, FilterConfig{})

	if len(kept) != 2 {
		paths := make([]string, len(kept))
		for i, f := range kept {
			paths[i] = f.Path
		}
		t.Fatalf("expected 2 dot-files kept (.env, .dockerignore), got %d: %v", len(kept), paths)
	}
	if stats.LowValue != 2 {
		t.Errorf("expected 2 low-value files, got %d", stats.LowValue)
	}
}

func TestFilterFiles_EdgeCase_Makefile(t *testing.T) {
	files := []SourceFile{
		makeFile("Makefile"),
		makeFile("src/Makefile"),
		makeFile("GNUmakefile"),
	}

	kept, _ := FilterFiles(files, FilterConfig{})

	if len(kept) != 3 {
		t.Fatalf("expected 3 Makefiles kept, got %d", len(kept))
	}
}

func TestFilterFiles_EdgeCase_Dockerfile(t *testing.T) {
	files := []SourceFile{
		makeFile("Dockerfile"),
		makeFile("Dockerfile.prod"),
		makeFile("docker/Dockerfile.dev"),
	}

	kept, _ := FilterFiles(files, FilterConfig{})

	if len(kept) != 3 {
		t.Fatalf("expected 3 Dockerfiles kept, got %d", len(kept))
	}
}

func TestFilterFiles_Stats_Correct(t *testing.T) {
	files := []SourceFile{
		makeFile("main.go"),           // kept
		makeFile("main_test.go"),      // test
		makeFile("vendor/dep.go"),     // vendor
		makeFile("image.png"),         // binary
		makeFile("README.md"),         // docs
		makeFile("schema.proto"),      // always-include
		makeFile("test/fixtures.sql"), // always-include (despite test dir)
	}

	kept, stats := FilterFiles(files, FilterConfig{})

	if stats.Total != 7 {
		t.Errorf("total: got %d, want 7", stats.Total)
	}
	if stats.Kept != 3 {
		t.Errorf("kept: got %d, want 3 (main.go, schema.proto, test/fixtures.sql)", stats.Kept)
	}
	if stats.Tests != 1 {
		t.Errorf("tests: got %d, want 1", stats.Tests)
	}
	if stats.Vendor != 1 {
		t.Errorf("vendor: got %d, want 1", stats.Vendor)
	}
	if stats.Binary != 1 {
		t.Errorf("binary: got %d, want 1", stats.Binary)
	}
	if stats.Docs != 1 {
		t.Errorf("docs: got %d, want 1", stats.Docs)
	}
	if len(kept) != 3 {
		t.Errorf("kept files: got %d, want 3", len(kept))
	}
}

func TestFilterFiles_StatsTotal(t *testing.T) {
	files := []SourceFile{
		makeFile("main.go"),
		makeFile("main_test.go"),
		makeFile("vendor/dep.go"),
		makeFile("image.png"),
		makeFile("README.md"),
	}

	_, stats := FilterFiles(files, FilterConfig{
		Exclude: []string{"nonexistent"},
	})

	// Verify that total = kept + tests + vendor + binary + docs + custom + oversized.
	sum := stats.Kept + stats.Tests + stats.Vendor + stats.Binary + stats.Docs + stats.Custom + stats.Oversized
	if sum != stats.Total {
		t.Errorf("stats don't add up: kept(%d) + tests(%d) + vendor(%d) + binary(%d) + docs(%d) + custom(%d) + oversized(%d) = %d, but total = %d",
			stats.Kept, stats.Tests, stats.Vendor, stats.Binary, stats.Docs, stats.Custom, stats.Oversized, sum, stats.Total)
	}
}

func TestFilterFiles_CustomGlobDoubleStarPattern(t *testing.T) {
	files := []SourceFile{
		makeFile("src/main.go"),
		makeFile("src/generated/model.go"),
		makeFile("lib/generated/types.go"),
	}

	kept, stats := FilterFiles(files, FilterConfig{
		Exclude: []string{"**/generated/*.go"},
	})

	if len(kept) != 1 {
		paths := make([]string, len(kept))
		for i, f := range kept {
			paths[i] = f.Path
		}
		t.Fatalf("expected 1 file kept, got %d: %v", len(kept), paths)
	}
	if kept[0].Path != "src/main.go" {
		t.Errorf("expected src/main.go, got %q", kept[0].Path)
	}
	if stats.Custom != 2 {
		t.Errorf("expected 2 custom exclusions, got %d", stats.Custom)
	}
}

func TestFilterFiles_CustomGlobTrailingDoubleStarPattern(t *testing.T) {
	files := []SourceFile{
		makeFile("firmware/main.c"),
		makeFile("firmware/third-party/direct.c"),
		makeFile("firmware/third-party/nested/deep.c"),
	}

	kept, stats := FilterFiles(files, FilterConfig{
		Exclude: []string{"firmware/third-party/**"},
	})

	if len(kept) != 1 {
		paths := make([]string, len(kept))
		for i, f := range kept {
			paths[i] = f.Path
		}
		t.Fatalf("expected 1 file kept, got %d: %v", len(kept), paths)
	}
	if kept[0].Path != "firmware/main.c" {
		t.Errorf("expected firmware/main.c, got %q", kept[0].Path)
	}
	if stats.Custom != 2 {
		t.Errorf("expected 2 custom exclusions, got %d", stats.Custom)
	}
}

func TestFilterFiles_AllFlagsEnabled(t *testing.T) {
	files := []SourceFile{
		makeFile("main.go"),
		makeFile("main_test.go"),
		makeFile("README.md"),
		makeFile("vendor/dep.go"), // still excluded
		makeFile("image.png"),     // still excluded (binary extension)
	}

	kept, stats := FilterFiles(files, FilterConfig{
		IncludeTests: true,
		IncludeDocs:  true,
	})

	if len(kept) != 3 {
		paths := make([]string, len(kept))
		for i, f := range kept {
			paths[i] = f.Path
		}
		t.Fatalf("expected 3 files kept, got %d: %v", len(kept), paths)
	}
	if stats.Tests != 0 {
		t.Errorf("expected 0 test exclusions, got %d", stats.Tests)
	}
	if stats.Docs != 0 {
		t.Errorf("expected 0 doc exclusions, got %d", stats.Docs)
	}
	if stats.Vendor != 1 {
		t.Errorf("expected 1 vendor exclusion, got %d", stats.Vendor)
	}
	if stats.Binary != 1 {
		t.Errorf("expected 1 binary exclusion, got %d", stats.Binary)
	}
}

func TestFilterFiles_MixedCategories(t *testing.T) {
	// A comprehensive test with files from every category.
	files := []SourceFile{
		// Kept
		makeFile("cmd/main.go"),
		makeFile("internal/handler.go"),
		makeFile("config.yaml"),
		makeFile("Dockerfile"),
		makeFile("Makefile"),
		makeFile(".env"),
		// Always-include
		makeFile("api/service.proto"),
		makeFile("db/schema.sql"),
		makeFile("api/types.graphql"),
		// Test files
		makeFile("internal/handler_test.go"),
		makeFile("test/integration.py"),
		makeFile("__tests__/component.js"),
		// Vendor
		makeFile("vendor/lib/dep.go"),
		makeFile("node_modules/pkg/index.js"),
		// Binary
		makeFile("assets/logo.png"),
		makeFile("bin/app.exe"),
		// Docs
		makeFile("README.md"),
		makeFile("docs/guide.md"),
	}

	kept, stats := FilterFiles(files, FilterConfig{})

	expectedKept := 9 // 6 regular + 3 always-include
	if len(kept) != expectedKept {
		paths := make([]string, len(kept))
		for i, f := range kept {
			paths[i] = f.Path
		}
		t.Fatalf("expected %d files kept, got %d: %v", expectedKept, len(kept), paths)
	}
	if stats.Tests != 3 {
		t.Errorf("tests: got %d, want 3", stats.Tests)
	}
	if stats.Vendor != 2 {
		t.Errorf("vendor: got %d, want 2", stats.Vendor)
	}
	if stats.Binary != 2 {
		t.Errorf("binary: got %d, want 2", stats.Binary)
	}
	if stats.Docs != 2 {
		t.Errorf("docs: got %d, want 2", stats.Docs)
	}
}

func TestFilterFiles_PreservesFileOrder(t *testing.T) {
	files := []SourceFile{
		makeFile("z.go"),
		makeFile("a.go"),
		makeFile("m.go"),
	}

	kept, _ := FilterFiles(files, FilterConfig{})

	if len(kept) != 3 {
		t.Fatalf("expected 3 files, got %d", len(kept))
	}
	if kept[0].Path != "z.go" || kept[1].Path != "a.go" || kept[2].Path != "m.go" {
		t.Errorf("filter should preserve order: got %v", []string{kept[0].Path, kept[1].Path, kept[2].Path})
	}
}

func TestFilterFiles_PreservesContent(t *testing.T) {
	content := "package main\n\nfunc main() {\n\tprintln(\"hello\")\n}\n"
	files := []SourceFile{
		makeFileWithContent("main.go", content),
	}

	kept, _ := FilterFiles(files, FilterConfig{})

	if len(kept) != 1 {
		t.Fatalf("expected 1 file, got %d", len(kept))
	}
	if kept[0].Content != content {
		t.Errorf("content not preserved: got %q, want %q", kept[0].Content, content)
	}
	if kept[0].LineCount != 5 {
		t.Errorf("line count not preserved: got %d, want 5", kept[0].LineCount)
	}
}

func TestIsTestFile(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"main_test.go", true},
		{"test_helper.py", true},
		{"component_spec.ts", true},
		{"widget_spec.js", true},
		{"test/helper.go", true},
		{"tests/integration.py", true},
		{"__tests__/component.js", true},
		{"spec/models/user.rb", true},
		{"src/__tests__/nested.js", true},
		{"main.go", false},
		{"testing.go", false},
		{"testdata/fixture.go", false},
		{"contest/entry.go", false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got := isTestFile(tt.path)
			if got != tt.want {
				t.Errorf("isTestFile(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

func TestIsInVendorDir(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"vendor/dep.go", true},
		{"node_modules/pkg/index.js", true},
		{"__pycache__/module.pyc", true},
		{".venv/lib/site.py", true},
		{"venv/lib/site.py", true},
		{"src/main.go", false},
		{"vendoring/tool.go", false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got := isInVendorDir(tt.path)
			if got != tt.want {
				t.Errorf("isInVendorDir(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

func TestIsBinaryFile(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    bool
	}{
		{"empty", "", false},
		{"text", "hello world\n", false},
		{"null at start", "\x00hello", true},
		{"null in middle", "hello\x00world", true},
		{"null at byte 511", strings.Repeat("A", 511) + "\x00" + strings.Repeat("B", 100), true},
		{"null at byte 512", strings.Repeat("A", 512) + "\x00" + strings.Repeat("B", 100), false},
		{"large text no null", strings.Repeat("hello\n", 1000), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isBinaryFile(tt.content)
			if got != tt.want {
				t.Errorf("isBinaryFile(%q...) = %v, want %v", tt.name, got, tt.want)
			}
		})
	}
}

func TestMatchesAnyGlob(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		patterns []string
		want     bool
	}{
		{"empty patterns", "main.go", nil, false},
		{"exact match", "main.go", []string{"main.go"}, true},
		{"extension glob", "main.go", []string{"*.go"}, true},
		{"no match", "main.go", []string{"*.py"}, false},
		{"path match", "src/main.go", []string{"src/main.go"}, true},
		{"double star prefix", "src/gen/model.go", []string{"**/gen/*.go"}, true},
		{"base match", "deep/nested/file.pb.go", []string{"*.pb.go"}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := matchesAnyGlob(tt.path, tt.patterns)
			if got != tt.want {
				t.Errorf("matchesAnyGlob(%q, %v) = %v, want %v", tt.path, tt.patterns, got, tt.want)
			}
		})
	}
}

func TestFilterFiles_VendorProtoAlwaysIncluded(t *testing.T) {
	// .proto inside vendor should still be included.
	files := []SourceFile{
		makeFile("vendor/google/api/annotations.proto"),
		makeFile("vendor/regular.go"),
	}

	kept, stats := FilterFiles(files, FilterConfig{})

	if len(kept) != 1 {
		t.Fatalf("expected 1 file kept, got %d", len(kept))
	}
	if kept[0].Path != "vendor/google/api/annotations.proto" {
		t.Errorf("expected proto file kept, got %q", kept[0].Path)
	}
	if stats.Vendor != 1 {
		t.Errorf("expected 1 vendor exclusion, got %d", stats.Vendor)
	}
}

func TestFilterFiles_NilConfigDefaults(t *testing.T) {
	// Zero-value FilterConfig should apply all default exclusions.
	files := []SourceFile{
		makeFile("main.go"),
		makeFile("main_test.go"),
		makeFile("vendor/dep.go"),
		makeFile("README.md"),
	}

	kept, _ := FilterFiles(files, FilterConfig{})

	if len(kept) != 1 {
		paths := make([]string, len(kept))
		for i, f := range kept {
			paths[i] = f.Path
		}
		t.Fatalf("expected 1 file with zero-value config, got %d: %v", len(kept), paths)
	}
	if kept[0].Path != "main.go" {
		t.Errorf("expected main.go, got %q", kept[0].Path)
	}
}

func TestFilterFiles_CustomIncludeAndExcludeCombined(t *testing.T) {
	files := []SourceFile{
		makeFile("main.go"),
		makeFile("main_test.go"),        // test excluded by default
		makeFile("integration_test.go"), // force-included via custom include
		makeFile("config.yaml"),         // excluded via custom exclude
	}

	kept, stats := FilterFiles(files, FilterConfig{
		Include: []string{"integration_test.go"},
		Exclude: []string{"*.yaml"},
	})

	if len(kept) != 2 {
		paths := make([]string, len(kept))
		for i, f := range kept {
			paths[i] = f.Path
		}
		t.Fatalf("expected 2 files kept, got %d: %v", len(kept), paths)
	}

	keptPaths := make(map[string]bool)
	for _, f := range kept {
		keptPaths[f.Path] = true
	}
	if !keptPaths["main.go"] {
		t.Error("expected main.go to be kept")
	}
	if !keptPaths["integration_test.go"] {
		t.Error("expected integration_test.go to be force-included")
	}
	if stats.Tests != 1 {
		t.Errorf("expected 1 test exclusion (main_test.go), got %d", stats.Tests)
	}
	if stats.Custom != 1 {
		t.Errorf("expected 1 custom exclusion (config.yaml), got %d", stats.Custom)
	}
}

func TestFilterFiles_MaxFileSize_ExcludesLargeFiles(t *testing.T) {
	small := strings.Repeat("x", 1000)
	large := strings.Repeat("x", 200000) // 200KB

	files := []SourceFile{
		makeFileWithContent("small.go", small),
		makeFileWithContent("huge.tsx", large),
		makeFileWithContent("big_fixture.json", large),
		makeFileWithContent("normal.ts", small),
	}

	kept, stats := FilterFiles(files, FilterConfig{MaxFileSize: 102400})

	if len(kept) != 2 {
		paths := make([]string, len(kept))
		for i, f := range kept {
			paths[i] = f.Path
		}
		t.Fatalf("expected 2 files kept, got %d: %v", len(kept), paths)
	}
	if stats.Oversized != 2 {
		t.Errorf("expected 2 oversized exclusions, got %d", stats.Oversized)
	}
}

func TestFilterFiles_MaxFileSize_ZeroDisablesLimit(t *testing.T) {
	large := strings.Repeat("x", 500000)

	files := []SourceFile{
		makeFileWithContent("big.go", large),
	}

	kept, stats := FilterFiles(files, FilterConfig{MaxFileSize: 0})

	if len(kept) != 1 {
		t.Fatalf("expected 1 file kept with no size limit, got %d", len(kept))
	}
	if stats.Oversized != 0 {
		t.Errorf("expected 0 oversized with no limit, got %d", stats.Oversized)
	}
}

func TestFilterFiles_MaxFileSize_CustomIncludeBypassesLimit(t *testing.T) {
	large := strings.Repeat("x", 200000)

	files := []SourceFile{
		makeFileWithContent("important.go", large),
	}

	kept, _ := FilterFiles(files, FilterConfig{
		MaxFileSize: 102400,
		Include:     []string{"important.go"},
	})

	if len(kept) != 1 {
		t.Fatal("expected force-included file to bypass size limit")
	}
}

func TestFilterFiles_MaxFileSize_AlwaysIncludeBypassesLimit(t *testing.T) {
	large := strings.Repeat("x", 200000)

	files := []SourceFile{
		makeFileWithContent("schema.proto", large),
		makeFileWithContent("migrations.sql", large),
	}

	kept, _ := FilterFiles(files, FilterConfig{MaxFileSize: 102400})

	if len(kept) != 2 {
		t.Fatalf("expected 2 always-include files kept despite size, got %d", len(kept))
	}
}

func TestFilterFiles_MaxFileSize_BoundaryValues(t *testing.T) {
	exactly := strings.Repeat("x", 1024)
	overBy1 := strings.Repeat("x", 1025)

	files := []SourceFile{
		makeFileWithContent("exact.go", exactly),
		makeFileWithContent("over.go", overBy1),
	}

	kept, stats := FilterFiles(files, FilterConfig{MaxFileSize: 1024})

	if len(kept) != 1 {
		t.Fatalf("expected 1 file kept at boundary, got %d", len(kept))
	}
	if kept[0].Path != "exact.go" {
		t.Errorf("expected exact.go kept, got %q", kept[0].Path)
	}
	if stats.Oversized != 1 {
		t.Errorf("expected 1 oversized, got %d", stats.Oversized)
	}
}
