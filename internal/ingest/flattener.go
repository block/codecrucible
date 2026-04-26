package ingest

import (
	"sort"
	"strconv"
	"strings"
)

// FlattenResult holds the output of the Flatten operation.
type FlattenResult struct {
	XML     string  // Repomix-compatible XML string.
	FileMap FileMap // In-memory file contents for snippet extraction.
	Tokens  int     // Token count (set to 0 here; counted by chunker later).
}

// FlattenConfig controls XML output formatting.
type FlattenConfig struct {
	Compress bool // When true, strips unnecessary whitespace from XML output.
}

// Flatten converts a slice of SourceFiles into a repomix-compatible XML document
// with numbered lines, and builds an in-memory FileMap for snippet extraction.
func Flatten(files []SourceFile, cfg FlattenConfig) FlattenResult {
	fm := make(FileMap, len(files))
	for _, f := range files {
		fm[f.Path] = f.Content
	}

	xml := buildXML(files, cfg)

	return FlattenResult{
		XML:     xml,
		FileMap: fm,
		Tokens:  0,
	}
}

// FlattenFileMapOnly builds only the FileMap without generating the full XML
// document. Use this when the caller will use streaming token counting and
// may not need the full XML (e.g. multi-chunk repos where the chunker
// rebuilds per-file XML from FileMap anyway).
func FlattenFileMapOnly(files []SourceFile) FlattenResult {
	fm := make(FileMap, len(files))
	for _, f := range files {
		fm[f.Path] = f.Content
	}
	return FlattenResult{FileMap: fm}
}

// BuildFullXML generates the complete repomix-format XML and stores it in the
// FlattenResult. Call this after FlattenFileMapOnly when the streaming token
// count confirms the repo fits in a single chunk.
func (fr *FlattenResult) BuildFullXML(files []SourceFile, cfg FlattenConfig) {
	fr.XML = buildXML(files, cfg)
}

// buildXML produces the full repomix-compatible XML document.
func buildXML(files []SourceFile, cfg FlattenConfig) string {
	if len(files) == 0 {
		return emptyXML(cfg)
	}

	var b strings.Builder
	// Pre-allocate a rough estimate to avoid repeated allocations.
	b.Grow(estimateXMLSize(files))

	writeHeader(&b, cfg)
	writeDirectoryStructure(&b, files, cfg)
	writeFiles(&b, files, cfg)

	return b.String()
}

// emptyXML produces a valid document for zero files.
func emptyXML(cfg FlattenConfig) string {
	var b strings.Builder
	writeHeader(&b, cfg)
	writeDirectoryStructure(&b, nil, cfg)

	if cfg.Compress {
		b.WriteString("<files>\n</files>")
	} else {
		b.WriteString("<files>\n</files>\n")
	}
	return b.String()
}

// writeHeader writes the repomix preamble and file_summary block.
func writeHeader(b *strings.Builder, cfg FlattenConfig) {
	// gap returns "\n" in non-compressed mode to add blank lines between sections.
	gap := "\n"
	if cfg.Compress {
		gap = ""
	}

	b.WriteString("This file is a merged representation of the entire codebase, combined into a single document by Repomix.\n")
	b.WriteString(gap)
	b.WriteString("<file_summary>\n")
	b.WriteString("<purpose>\n")
	b.WriteString("This file contains a packed representation of the entire repository's contents.\n")
	b.WriteString("It is designed to be easily consumable by AI systems for analysis, code review,\n")
	b.WriteString("or other automated processes.\n")
	b.WriteString("</purpose>\n")
	b.WriteString(gap)
	b.WriteString("<file_format>\n")
	b.WriteString("The content is organized as follows:\n")
	b.WriteString("1. This summary section\n")
	b.WriteString("2. Repository structure\n")
	b.WriteString("3. Repository files, each preceded by its file path as an XML tag\n")
	b.WriteString(gap)
	b.WriteString("Each file's content is preceded by a line number prefix for reference.\n")
	b.WriteString("</file_format>\n")
	b.WriteString(gap)
	b.WriteString("<usage_guidelines>\n")
	b.WriteString("- Use the file path to understand the repository structure\n")
	b.WriteString("- Use line numbers for precise code references\n")
	b.WriteString("- Cross-reference files to understand dependencies and relationships\n")
	b.WriteString("</usage_guidelines>\n")
	b.WriteString(gap)
	b.WriteString("<notes>\n")
	b.WriteString("- Some binary files may have been excluded\n")
	b.WriteString("- Files are sorted by path for consistent ordering\n")
	b.WriteString("</notes>\n")
	b.WriteString("</file_summary>\n")
	b.WriteString(gap)
}

// writeDirectoryStructure writes the directory_structure block.
func writeDirectoryStructure(b *strings.Builder, files []SourceFile, cfg FlattenConfig) {
	b.WriteString("<directory_structure>\n")
	if len(files) > 0 {
		// Sort paths for deterministic output.
		paths := make([]string, len(files))
		for i, f := range files {
			paths[i] = f.Path
		}
		sort.Strings(paths)
		for _, p := range paths {
			b.WriteString(p)
			b.WriteByte('\n')
		}
	}
	if cfg.Compress {
		b.WriteString("</directory_structure>\n")
	} else {
		b.WriteString("</directory_structure>\n\n")
	}
}

// writeFiles writes the <files> block with numbered lines for each file.
func writeFiles(b *strings.Builder, files []SourceFile, cfg FlattenConfig) {
	// Sort files by path for deterministic output.
	sorted := make([]SourceFile, len(files))
	copy(sorted, files)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Path < sorted[j].Path
	})

	b.WriteString("<files>\n")

	for i, f := range sorted {
		writeFileElement(b, f)
		// Add blank line between files in non-compressed mode, but not after the last.
		if !cfg.Compress && i < len(sorted)-1 {
			b.WriteByte('\n')
		}
	}

	b.WriteString("</files>\n")
}

// writeFileElement writes a single <file path="..."> element with numbered lines.
func writeFileElement(b *strings.Builder, f SourceFile) {
	escapedPath := EscapeXMLAttr(f.Path)
	b.WriteString("<file path=\"")
	b.WriteString(escapedPath)
	b.WriteString("\">\n")

	writeNumberedLines(b, f.Content)

	b.WriteString("</file>\n")
}

// writeNumberedLines writes the file content with line numbers in repomix format.
// Format: "{padded_number} | {line}\n" where padding is based on total line count.
func writeNumberedLines(b *strings.Builder, content string) {
	if content == "" {
		return
	}

	lines := SplitLines(content)
	totalLines := len(lines)
	padding := len(strconv.Itoa(totalLines))

	for i, line := range lines {
		num := i + 1
		b.WriteString(padLeft(strconv.Itoa(num), padding))
		b.WriteString(" | ")
		b.WriteString(EscapeXMLContent(line))
		b.WriteByte('\n')
	}
}

// SplitLines splits content into lines, handling the trailing newline edge case.
// A file with content "a\nb\n" has 2 lines: ["a", "b"].
// A file with content "a\nb" (no trailing newline) has 2 lines: ["a", "b"].
// An empty string returns nil.
func SplitLines(content string) []string {
	if content == "" {
		return nil
	}
	// Remove a single trailing newline to avoid an empty phantom line.
	trimmed := strings.TrimSuffix(content, "\n")
	if trimmed == "" {
		// Content was just "\n" — treat as a single empty line.
		return []string{""}
	}
	return strings.Split(trimmed, "\n")
}

// EnvelopeXML returns the header and directory-structure XML without any file
// content. Used by the streaming token counter to measure envelope overhead
// without building the full document.
func EnvelopeXML(paths []string, cfg FlattenConfig) string {
	var b strings.Builder
	writeHeader(&b, cfg)

	// Write directory structure from paths directly (no SourceFile needed).
	b.WriteString("<directory_structure>\n")
	sorted := make([]string, len(paths))
	copy(sorted, paths)
	sort.Strings(sorted)
	for _, p := range sorted {
		b.WriteString(p)
		b.WriteByte('\n')
	}
	if cfg.Compress {
		b.WriteString("</directory_structure>\n")
	} else {
		b.WriteString("</directory_structure>\n\n")
	}

	b.WriteString("<files>\n</files>\n")
	return b.String()
}

// padLeft pads s with spaces on the left to reach the given width.
func padLeft(s string, width int) string {
	if len(s) >= width {
		return s
	}
	return strings.Repeat(" ", width-len(s)) + s
}

// EscapeXMLContent escapes characters that are special in XML text content.
func EscapeXMLContent(s string) string {
	// Fast path: if no special chars, return as-is.
	if !strings.ContainsAny(s, "&<>") {
		return s
	}
	var b strings.Builder
	b.Grow(len(s) + 10) // slight overallocation for escapes
	for _, r := range s {
		switch r {
		case '&':
			b.WriteString("&amp;")
		case '<':
			b.WriteString("&lt;")
		case '>':
			b.WriteString("&gt;")
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// EscapeXMLAttr escapes characters that are special in XML attribute values.
func EscapeXMLAttr(s string) string {
	if !strings.ContainsAny(s, "&<>\"'") {
		return s
	}
	var b strings.Builder
	b.Grow(len(s) + 10)
	for _, r := range s {
		switch r {
		case '&':
			b.WriteString("&amp;")
		case '<':
			b.WriteString("&lt;")
		case '>':
			b.WriteString("&gt;")
		case '"':
			b.WriteString("&quot;")
		case '\'':
			b.WriteString("&apos;")
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// estimateXMLSize estimates the total output size for pre-allocation.
func estimateXMLSize(files []SourceFile) int {
	// Header + structure is roughly 1KB.
	size := 1024
	for _, f := range files {
		// path tag overhead (~50 bytes) + content + line numbers (~8 bytes per line).
		size += 50 + len(f.Content) + f.LineCount*8
	}
	return size
}
