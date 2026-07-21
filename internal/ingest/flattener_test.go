package ingest

import (
	"fmt"
	"strings"
	"testing"
)

func TestFlatten_EmptyInput(t *testing.T) {
	result := Flatten(nil, FlattenConfig{})

	if len(result.FileMap) != 0 {
		t.Errorf("FileMap should be empty, got %d entries", len(result.FileMap))
	}
	if result.Tokens != 0 {
		t.Errorf("Tokens should be 0, got %d", result.Tokens)
	}
	// Should still produce valid XML structure.
	if !strings.Contains(result.XML, "<files>") {
		t.Error("empty XML should contain <files> element")
	}
	if !strings.Contains(result.XML, "</files>") {
		t.Error("empty XML should contain </files> closing element")
	}
	if !strings.Contains(result.XML, "<directory_structure>") {
		t.Error("empty XML should contain directory_structure element")
	}
}

func TestFlatten_EmptySlice(t *testing.T) {
	result := Flatten([]SourceFile{}, FlattenConfig{})

	if len(result.FileMap) != 0 {
		t.Errorf("FileMap should be empty, got %d entries", len(result.FileMap))
	}
	if !strings.Contains(result.XML, "<files>") {
		t.Error("empty XML should contain <files> element")
	}
}

func TestFlatten_SingleFile(t *testing.T) {
	files := []SourceFile{
		{
			Path:      "main.go",
			Content:   "package main\n\nfunc main() {}\n",
			LineCount: 3,
			Language:  "go",
		},
	}

	result := Flatten(files, FlattenConfig{})

	// Check FileMap.
	if content, ok := result.FileMap["main.go"]; !ok {
		t.Error("FileMap should contain main.go")
	} else if content != "package main\n\nfunc main() {}\n" {
		t.Errorf("FileMap content mismatch: got %q", content)
	}

	// Check XML structure.
	if !strings.Contains(result.XML, `<file path="main.go">`) {
		t.Error("XML should contain file element with path attribute")
	}
	if !strings.Contains(result.XML, "</file>") {
		t.Error("XML should contain closing file tag")
	}
	if !strings.Contains(result.XML, "1 | package main") {
		t.Error("XML should contain numbered line 1")
	}
	if !strings.Contains(result.XML, "2 | ") {
		t.Error("XML should contain numbered line 2 (empty line)")
	}
	if !strings.Contains(result.XML, "3 | func main() {}") {
		t.Error("XML should contain numbered line 3")
	}
}

func TestFlatten_LineNumberPadding(t *testing.T) {
	// Create a file with 12 lines to test padding (2-digit numbers).
	var content strings.Builder
	for i := 1; i <= 12; i++ {
		fmt.Fprintf(&content, "line %d\n", i)
	}

	files := []SourceFile{
		{
			Path:      "big.txt",
			Content:   content.String(),
			LineCount: 12,
			Language:  "",
		},
	}

	result := Flatten(files, FlattenConfig{})

	// Single-digit lines should be padded.
	if !strings.Contains(result.XML, " 1 | line 1") {
		t.Error("line 1 should be padded: ' 1 | line 1'")
	}
	if !strings.Contains(result.XML, " 9 | line 9") {
		t.Error("line 9 should be padded: ' 9 | line 9'")
	}
	// Two-digit lines should not be padded.
	if !strings.Contains(result.XML, "10 | line 10") {
		t.Error("line 10 should not be padded: '10 | line 10'")
	}
	if !strings.Contains(result.XML, "12 | line 12") {
		t.Error("line 12 should not be padded: '12 | line 12'")
	}
}

func TestFlatten_LineNumberPadding_ThreeDigits(t *testing.T) {
	// Create a file with 100 lines.
	var content strings.Builder
	for i := 1; i <= 100; i++ {
		fmt.Fprintf(&content, "L%d\n", i)
	}

	files := []SourceFile{
		{
			Path:      "hundred.txt",
			Content:   content.String(),
			LineCount: 100,
			Language:  "",
		},
	}

	result := Flatten(files, FlattenConfig{})

	// Check 3-digit padding.
	if !strings.Contains(result.XML, "  1 | L1") {
		t.Errorf("line 1 should have 2 spaces of padding for 3-digit width")
	}
	if !strings.Contains(result.XML, " 10 | L10") {
		t.Errorf("line 10 should have 1 space of padding for 3-digit width")
	}
	if !strings.Contains(result.XML, "100 | L100") {
		t.Errorf("line 100 should have no padding")
	}
}

func TestFlatten_FileMap_AllFilesPresent(t *testing.T) {
	files := []SourceFile{
		{Path: "a.go", Content: "package a\n", LineCount: 1, Language: "go"},
		{Path: "b/c.go", Content: "package c\n", LineCount: 1, Language: "go"},
		{Path: "d/e/f.py", Content: "print('hi')\n", LineCount: 1, Language: "python"},
	}

	result := Flatten(files, FlattenConfig{})

	if len(result.FileMap) != 3 {
		t.Fatalf("FileMap should have 3 entries, got %d", len(result.FileMap))
	}

	expected := map[string]string{
		"a.go":     "package a\n",
		"b/c.go":   "package c\n",
		"d/e/f.py": "print('hi')\n",
	}

	for path, want := range expected {
		got, ok := result.FileMap[path]
		if !ok {
			t.Errorf("FileMap missing key %q", path)
			continue
		}
		if got != want {
			t.Errorf("FileMap[%q] = %q, want %q", path, got, want)
		}
	}
}

func TestFlatten_NoTrailingNewline(t *testing.T) {
	files := []SourceFile{
		{
			Path:      "no_newline.txt",
			Content:   "line one\nline two",
			LineCount: 2,
			Language:  "",
		},
	}

	result := Flatten(files, FlattenConfig{})

	// Should have exactly 2 lines.
	if !strings.Contains(result.XML, "1 | line one") {
		t.Error("should contain line 1")
	}
	if !strings.Contains(result.XML, "2 | line two") {
		t.Error("should contain line 2")
	}

	// Should NOT have a line 3.
	if strings.Contains(result.XML, "3 |") {
		t.Error("should not have a phantom line 3 from missing trailing newline")
	}
}

func TestFlatten_TrailingNewline(t *testing.T) {
	files := []SourceFile{
		{
			Path:      "with_newline.txt",
			Content:   "line one\nline two\n",
			LineCount: 2,
			Language:  "",
		},
	}

	result := Flatten(files, FlattenConfig{})

	// Should have exactly 2 lines.
	if !strings.Contains(result.XML, "1 | line one") {
		t.Error("should contain line 1")
	}
	if !strings.Contains(result.XML, "2 | line two") {
		t.Error("should contain line 2")
	}
	if strings.Contains(result.XML, "3 |") {
		t.Error("should not have phantom line 3")
	}
}

func TestFlatten_OnlyNewlineContent(t *testing.T) {
	files := []SourceFile{
		{
			Path:      "just_newline.txt",
			Content:   "\n",
			LineCount: 1,
			Language:  "",
		},
	}

	result := Flatten(files, FlattenConfig{})

	// Content "\n" should produce one empty line.
	if !strings.Contains(result.XML, "1 | \n") {
		t.Error("content '\\n' should produce a single empty numbered line")
	}
}

func TestFlatten_XMLSpecialCharacterEscaping(t *testing.T) {
	files := []SourceFile{
		{
			Path:      "special.html",
			Content:   "<div class=\"test\">&amp; foo > bar</div>\n",
			LineCount: 1,
			Language:  "html",
		},
	}

	result := Flatten(files, FlattenConfig{})

	// Content should have XML special chars escaped.
	if !strings.Contains(result.XML, "&lt;div class=\"test\"&gt;&amp;amp; foo &gt; bar&lt;/div&gt;") {
		// Find the actual line for debugging.
		for _, line := range strings.Split(result.XML, "\n") {
			if strings.Contains(line, "1 |") && strings.Contains(line, "div") {
				t.Errorf("XML content escaping incorrect, got line: %q", line)
				return
			}
		}
		t.Error("could not find the file content line in XML output")
	}
}

func TestFlatten_XMLEscaping_Ampersand(t *testing.T) {
	files := []SourceFile{
		{Path: "amp.txt", Content: "a & b\n", LineCount: 1},
	}
	result := Flatten(files, FlattenConfig{})
	if !strings.Contains(result.XML, "1 | a &amp; b") {
		t.Errorf("& should be escaped to &amp; in XML content")
	}
}

func TestFlatten_XMLEscaping_LessThan(t *testing.T) {
	files := []SourceFile{
		{Path: "lt.txt", Content: "a < b\n", LineCount: 1},
	}
	result := Flatten(files, FlattenConfig{})
	if !strings.Contains(result.XML, "1 | a &lt; b") {
		t.Errorf("< should be escaped to &lt; in XML content")
	}
}

func TestFlatten_XMLEscaping_GreaterThan(t *testing.T) {
	files := []SourceFile{
		{Path: "gt.txt", Content: "a > b\n", LineCount: 1},
	}
	result := Flatten(files, FlattenConfig{})
	if !strings.Contains(result.XML, "1 | a &gt; b") {
		t.Errorf("> should be escaped to &gt; in XML content")
	}
}

func TestFlatten_XMLAttrEscaping_Path(t *testing.T) {
	files := []SourceFile{
		{Path: "dir/file\"name.txt", Content: "content\n", LineCount: 1},
	}
	result := Flatten(files, FlattenConfig{})
	if !strings.Contains(result.XML, `<file path="dir/file&quot;name.txt">`) {
		t.Errorf("double quotes in path should be escaped in attribute")
	}
}

func TestFlatten_UnicodePreservation(t *testing.T) {
	files := []SourceFile{
		{
			Path:      "unicode.txt",
			Content:   "Hello 世界\nこんにちは\n🎉 emoji\n",
			LineCount: 3,
			Language:  "",
		},
	}

	result := Flatten(files, FlattenConfig{})

	if !strings.Contains(result.XML, "1 | Hello 世界") {
		t.Error("Chinese characters should be preserved")
	}
	if !strings.Contains(result.XML, "2 | こんにちは") {
		t.Error("Japanese characters should be preserved")
	}
	if !strings.Contains(result.XML, "3 | 🎉 emoji") {
		t.Error("emoji should be preserved")
	}

	// FileMap should also preserve Unicode.
	if content, ok := result.FileMap["unicode.txt"]; ok {
		if !strings.Contains(content, "世界") {
			t.Error("FileMap should preserve Unicode content")
		}
	} else {
		t.Error("FileMap should contain unicode.txt")
	}
}

func TestFlatten_LargeFile(t *testing.T) {
	// Create a file with 10,000+ lines.
	var content strings.Builder
	lineCount := 10500
	for i := 1; i <= lineCount; i++ {
		fmt.Fprintf(&content, "line number %d with some content\n", i)
	}

	files := []SourceFile{
		{
			Path:      "large.txt",
			Content:   content.String(),
			LineCount: lineCount,
			Language:  "",
		},
	}

	result := Flatten(files, FlattenConfig{})

	// Check that all lines are numbered.
	// Line 1 should be padded to 5 digits.
	if !strings.Contains(result.XML, "    1 | line number 1 with some content") {
		t.Error("first line should have 4 spaces padding (5-digit width)")
	}
	if !strings.Contains(result.XML, "10500 | line number 10500 with some content") {
		t.Error("last line should be present with no padding")
	}

	// Verify FileMap.
	if _, ok := result.FileMap["large.txt"]; !ok {
		t.Error("FileMap should contain large.txt")
	}

	// Verify tokens is 0 (set by chunker later).
	if result.Tokens != 0 {
		t.Errorf("Tokens should be 0, got %d", result.Tokens)
	}
}

func TestFlatten_Compress(t *testing.T) {
	files := []SourceFile{
		{Path: "a.go", Content: "package a\n", LineCount: 1, Language: "go"},
	}

	normal := Flatten(files, FlattenConfig{Compress: false})
	compressed := Flatten(files, FlattenConfig{Compress: true})

	// Compressed output should be shorter (no blank lines between sections).
	if len(compressed.XML) >= len(normal.XML) {
		t.Errorf("compressed XML (%d bytes) should be shorter than normal (%d bytes)",
			len(compressed.XML), len(normal.XML))
	}

	// Both should contain the file content.
	if !strings.Contains(compressed.XML, "1 | package a") {
		t.Error("compressed XML should still contain numbered lines")
	}
	if !strings.Contains(compressed.XML, `<file path="a.go">`) {
		t.Error("compressed XML should still contain file element")
	}

	// Normal should have blank lines between sections.
	if !strings.Contains(normal.XML, "</purpose>\n\n") {
		t.Error("normal XML should have blank line after </purpose>")
	}

	// Compressed should NOT have blank lines between sections.
	if strings.Contains(compressed.XML, "</purpose>\n\n") {
		t.Error("compressed XML should not have blank line after </purpose>")
	}
}

func TestFlatten_Compress_ReducesSize(t *testing.T) {
	// Create multiple files.
	files := []SourceFile{
		{Path: "a.go", Content: "package a\n\nfunc A() {}\n", LineCount: 3, Language: "go"},
		{Path: "b.go", Content: "package b\n\nfunc B() {}\n", LineCount: 3, Language: "go"},
		{Path: "c.go", Content: "package c\n\nfunc C() {}\n", LineCount: 3, Language: "go"},
	}

	normal := Flatten(files, FlattenConfig{Compress: false})
	compressed := Flatten(files, FlattenConfig{Compress: true})

	if len(compressed.XML) >= len(normal.XML) {
		t.Errorf("compressed (%d bytes) should be smaller than normal (%d bytes)",
			len(compressed.XML), len(normal.XML))
	}
}

func TestFlatten_DirectoryStructure(t *testing.T) {
	files := []SourceFile{
		{Path: "b/handler.go", Content: "package b\n", LineCount: 1, Language: "go"},
		{Path: "a/main.go", Content: "package a\n", LineCount: 1, Language: "go"},
		{Path: "c.txt", Content: "hello\n", LineCount: 1, Language: ""},
	}

	result := Flatten(files, FlattenConfig{})

	// Directory structure should list paths sorted.
	dsStart := strings.Index(result.XML, "<directory_structure>")
	dsEnd := strings.Index(result.XML, "</directory_structure>")
	if dsStart == -1 || dsEnd == -1 {
		t.Fatal("missing directory_structure element")
	}
	ds := result.XML[dsStart:dsEnd]

	aPos := strings.Index(ds, "a/main.go")
	bPos := strings.Index(ds, "b/handler.go")
	cPos := strings.Index(ds, "c.txt")

	if aPos == -1 || bPos == -1 || cPos == -1 {
		t.Fatalf("directory structure missing paths, got: %s", ds)
	}
	if !(aPos < bPos && bPos < cPos) {
		t.Error("directory structure paths should be sorted alphabetically")
	}
}

func TestFlatten_FilesSortedByPath(t *testing.T) {
	files := []SourceFile{
		{Path: "z.go", Content: "package z\n", LineCount: 1, Language: "go"},
		{Path: "a.go", Content: "package a\n", LineCount: 1, Language: "go"},
		{Path: "m.go", Content: "package m\n", LineCount: 1, Language: "go"},
	}

	result := Flatten(files, FlattenConfig{})

	aPos := strings.Index(result.XML, `<file path="a.go">`)
	mPos := strings.Index(result.XML, `<file path="m.go">`)
	zPos := strings.Index(result.XML, `<file path="z.go">`)

	if aPos == -1 || mPos == -1 || zPos == -1 {
		t.Fatal("not all file elements found in XML")
	}
	if !(aPos < mPos && mPos < zPos) {
		t.Error("files should be sorted by path in XML output")
	}
}

func TestFlatten_HeaderPresent(t *testing.T) {
	files := []SourceFile{
		{Path: "test.go", Content: "package test\n", LineCount: 1, Language: "go"},
	}

	result := Flatten(files, FlattenConfig{})

	if !strings.HasPrefix(result.XML, "This file is a merged representation") {
		t.Error("XML should start with repomix header text")
	}
	if !strings.Contains(result.XML, "<file_summary>") {
		t.Error("XML should contain file_summary element")
	}
	if !strings.Contains(result.XML, "<purpose>") {
		t.Error("XML should contain purpose element")
	}
	if !strings.Contains(result.XML, "<file_format>") {
		t.Error("XML should contain file_format element")
	}
	if !strings.Contains(result.XML, "<usage_guidelines>") {
		t.Error("XML should contain usage_guidelines element")
	}
}

func TestFlatten_TokensAlwaysZero(t *testing.T) {
	files := []SourceFile{
		{Path: "a.go", Content: "package a\n", LineCount: 1, Language: "go"},
	}

	result := Flatten(files, FlattenConfig{})
	if result.Tokens != 0 {
		t.Errorf("Tokens should always be 0 (set by chunker), got %d", result.Tokens)
	}
}

func TestFlatten_MultipleFiles(t *testing.T) {
	files := []SourceFile{
		{Path: "cmd/main.go", Content: "package main\n\nimport \"fmt\"\n\nfunc main() {\n\tfmt.Println(\"hello\")\n}\n", LineCount: 7, Language: "go"},
		{Path: "lib/util.go", Content: "package lib\n\nfunc Add(a, b int) int {\n\treturn a + b\n}\n", LineCount: 5, Language: "go"},
	}

	result := Flatten(files, FlattenConfig{})

	// Both files should be in FileMap.
	if len(result.FileMap) != 2 {
		t.Fatalf("FileMap should have 2 entries, got %d", len(result.FileMap))
	}

	// Both files should appear in XML.
	if !strings.Contains(result.XML, `<file path="cmd/main.go">`) {
		t.Error("XML should contain cmd/main.go")
	}
	if !strings.Contains(result.XML, `<file path="lib/util.go">`) {
		t.Error("XML should contain lib/util.go")
	}
}

func TestFlatten_EmptyFileContent(t *testing.T) {
	files := []SourceFile{
		{Path: "empty.txt", Content: "", LineCount: 0, Language: ""},
	}

	result := Flatten(files, FlattenConfig{})

	// File element should exist but have no numbered lines.
	if !strings.Contains(result.XML, `<file path="empty.txt">`) {
		t.Error("XML should contain empty file element")
	}

	// Should go directly from opening tag to closing tag.
	idx := strings.Index(result.XML, `<file path="empty.txt">`)
	if idx == -1 {
		t.Fatal("could not find file element")
	}
	// After the opening tag and newline, the next line should be </file>.
	afterTag := result.XML[idx+len(`<file path="empty.txt">`)+1:]
	if !strings.HasPrefix(afterTag, "</file>") {
		t.Errorf("empty file should have no content between tags, got: %q", afterTag[:min(50, len(afterTag))])
	}
}

func TestSplitLines(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    []string
	}{
		{"empty", "", nil},
		{"single line no newline", "hello", []string{"hello"}},
		{"single line with newline", "hello\n", []string{"hello"}},
		{"two lines with newline", "a\nb\n", []string{"a", "b"}},
		{"two lines no trailing", "a\nb", []string{"a", "b"}},
		{"blank lines", "a\n\nb\n", []string{"a", "", "b"}},
		{"only newline", "\n", []string{""}},
		{"multiple blank lines", "\n\n\n", []string{"", "", ""}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SplitLines(tt.content)
			if tt.want == nil {
				// SplitLines returns nil for empty content via early return.
				if len(got) != 0 {
					t.Errorf("SplitLines(%q) = %v, want nil/empty", tt.content, got)
				}
				return
			}
			if len(got) != len(tt.want) {
				t.Errorf("SplitLines(%q) has %d lines, want %d: got %v", tt.content, len(got), len(tt.want), got)
				return
			}
			for i, w := range tt.want {
				if got[i] != w {
					t.Errorf("SplitLines(%q)[%d] = %q, want %q", tt.content, i, got[i], w)
				}
			}
		})
	}
}

func TestPadLeft(t *testing.T) {
	tests := []struct {
		s     string
		width int
		want  string
	}{
		{"1", 1, "1"},
		{"1", 3, "  1"},
		{"10", 3, " 10"},
		{"100", 3, "100"},
		{"1000", 3, "1000"},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%s_w%d", tt.s, tt.width), func(t *testing.T) {
			got := padLeft(tt.s, tt.width)
			if got != tt.want {
				t.Errorf("padLeft(%q, %d) = %q, want %q", tt.s, tt.width, got, tt.want)
			}
		})
	}
}

func TestEscapeXMLContent(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"no special chars", "hello world", "hello world"},
		{"ampersand", "a & b", "a &amp; b"},
		{"less than", "a < b", "a &lt; b"},
		{"greater than", "a > b", "a &gt; b"},
		{"all special", "<tag>&value</tag>", "&lt;tag&gt;&amp;value&lt;/tag&gt;"},
		{"empty string", "", ""},
		{"unicode", "Hello 世界", "Hello 世界"},
		{"multiple amps", "a && b && c", "a &amp;&amp; b &amp;&amp; c"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := EscapeXMLContent(tt.input)
			if got != tt.want {
				t.Errorf("EscapeXMLContent(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestEscapeXMLAttr(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"no special chars", "path/to/file.go", "path/to/file.go"},
		{"double quote", `path/"file".go`, `path/&quot;file&quot;.go`},
		{"single quote", "it's", "it&apos;s"},
		{"ampersand", "a&b", "a&amp;b"},
		{"mixed", `<"path">`, `&lt;&quot;path&quot;&gt;`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := EscapeXMLAttr(tt.input)
			if got != tt.want {
				t.Errorf("EscapeXMLAttr(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestFlatten_LineNumberAccuracy(t *testing.T) {
	// Verify exact line number format for specific files.
	tests := []struct {
		name      string
		content   string
		wantLines []string
	}{
		{
			name:    "single line",
			content: "hello\n",
			wantLines: []string{
				"1 | hello",
			},
		},
		{
			name:    "three lines",
			content: "a\nb\nc\n",
			wantLines: []string{
				"1 | a",
				"2 | b",
				"3 | c",
			},
		},
		{
			name:    "ten lines - padding kicks in",
			content: "1\n2\n3\n4\n5\n6\n7\n8\n9\n10\n",
			wantLines: []string{
				" 1 | 1",
				" 2 | 2",
				" 9 | 9",
				"10 | 10",
			},
		},
		{
			name:    "no trailing newline",
			content: "first\nsecond",
			wantLines: []string{
				"1 | first",
				"2 | second",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			files := []SourceFile{
				{Path: "test.txt", Content: tt.content, LineCount: countLines(tt.content)},
			}
			result := Flatten(files, FlattenConfig{})

			for _, want := range tt.wantLines {
				if !strings.Contains(result.XML, want) {
					t.Errorf("expected line %q not found in XML output", want)
				}
			}
		})
	}
}

func TestFlatten_XMLWellFormedness(t *testing.T) {
	files := []SourceFile{
		{Path: "a.go", Content: "package a\n", LineCount: 1, Language: "go"},
		{Path: "b.go", Content: "package b\n", LineCount: 1, Language: "go"},
	}

	result := Flatten(files, FlattenConfig{})

	// Count opening and closing tags.
	pairs := []struct {
		open  string
		close string
	}{
		{"<file_summary>", "</file_summary>"},
		{"<purpose>", "</purpose>"},
		{"<file_format>", "</file_format>"},
		{"<usage_guidelines>", "</usage_guidelines>"},
		{"<notes>", "</notes>"},
		{"<directory_structure>", "</directory_structure>"},
		{"<files>", "</files>"},
	}

	for _, p := range pairs {
		openCount := strings.Count(result.XML, p.open)
		closeCount := strings.Count(result.XML, p.close)
		if openCount != closeCount {
			t.Errorf("mismatched tags: %s (%d) vs %s (%d)", p.open, openCount, p.close, closeCount)
		}
		if openCount == 0 {
			t.Errorf("missing element: %s", p.open)
		}
	}

	// Check file tags match.
	fileOpens := strings.Count(result.XML, "<file path=")
	fileCloses := strings.Count(result.XML, "</file>")
	if fileOpens != fileCloses {
		t.Errorf("mismatched file tags: %d opens vs %d closes", fileOpens, fileCloses)
	}
	if fileOpens != 2 {
		t.Errorf("expected 2 file elements, got %d", fileOpens)
	}
}

func TestFlatten_Compress_StillValidStructure(t *testing.T) {
	files := []SourceFile{
		{Path: "a.go", Content: "package a\n", LineCount: 1, Language: "go"},
	}

	result := Flatten(files, FlattenConfig{Compress: true})

	// All required elements should still be present.
	required := []string{
		"<file_summary>", "</file_summary>",
		"<directory_structure>", "</directory_structure>",
		"<files>", "</files>",
		`<file path="a.go">`, "</file>",
		"1 | package a",
	}

	for _, r := range required {
		if !strings.Contains(result.XML, r) {
			t.Errorf("compressed XML missing required element: %q", r)
		}
	}
}

func TestFlatten_Compress_NoBlanks(t *testing.T) {
	files := []SourceFile{
		{Path: "a.go", Content: "package a\n", LineCount: 1, Language: "go"},
		{Path: "b.go", Content: "package b\n", LineCount: 1, Language: "go"},
	}

	result := Flatten(files, FlattenConfig{Compress: true})

	// Should not have double newlines.
	if strings.Contains(result.XML, "\n\n") {
		// Find where the double newline is for debugging.
		idx := strings.Index(result.XML, "\n\n")
		start := idx - 30
		if start < 0 {
			start = 0
		}
		end := idx + 30
		if end > len(result.XML) {
			end = len(result.XML)
		}
		t.Errorf("compressed XML should not have double newlines, found at position %d: %q", idx, result.XML[start:end])
	}
}

func TestFlatten_LargeFile_LineCount(t *testing.T) {
	// Verify all 10K lines are present.
	lineCount := 10000
	var content strings.Builder
	for i := 1; i <= lineCount; i++ {
		fmt.Fprintf(&content, "L%d\n", i)
	}

	files := []SourceFile{
		{Path: "big.txt", Content: content.String(), LineCount: lineCount},
	}

	result := Flatten(files, FlattenConfig{})

	// Count the numbered lines in the file element.
	fileStart := strings.Index(result.XML, `<file path="big.txt">`)
	fileEnd := strings.Index(result.XML, "</file>")
	if fileStart == -1 || fileEnd == -1 {
		t.Fatal("could not find file element boundaries")
	}

	fileContent := result.XML[fileStart:fileEnd]
	// Count lines that match the number pattern.
	lines := strings.Split(fileContent, "\n")
	numberedCount := 0
	for _, line := range lines {
		// Skip the opening tag line.
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "<") {
			continue
		}
		numberedCount++
	}

	if numberedCount != lineCount {
		t.Errorf("expected %d numbered lines, got %d", lineCount, numberedCount)
	}
}

func TestFlatten_MixedContent(t *testing.T) {
	// Realistic mix of files with different characteristics.
	files := []SourceFile{
		{Path: "main.go", Content: "package main\n\nfunc main() {}\n", LineCount: 3, Language: "go"},
		{Path: "config.yaml", Content: "key: value\nlist:\n  - item1\n  - item2\n", LineCount: 4, Language: "yaml"},
		{Path: "README.md", Content: "# Project\n\nDescription with <html> tags & special chars.\n", LineCount: 3, Language: "markdown"},
		{Path: "empty.txt", Content: "", LineCount: 0, Language: ""},
	}

	result := Flatten(files, FlattenConfig{})

	// Verify all files are in FileMap.
	if len(result.FileMap) != 4 {
		t.Errorf("FileMap should have 4 entries, got %d", len(result.FileMap))
	}

	// Verify HTML tags in README are escaped.
	if !strings.Contains(result.XML, "&lt;html&gt;") {
		t.Error("HTML tags in content should be escaped")
	}
	if !strings.Contains(result.XML, "&amp; special") {
		t.Error("& in content should be escaped")
	}
}
