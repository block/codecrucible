package ingest

import (
	"bytes"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"

	ignore "github.com/sabhiram/go-gitignore"
)

// SourceFile represents a single source file with metadata.
type SourceFile struct {
	Path      string // Relative path from repo root (e.g., "src/api/handlers.go")
	Content   string // Full file content (UTF-8 validated)
	LineCount int    // Number of lines
	Language  string // Inferred language (e.g., "go", "python")
}

// FileMap maps file paths to their content for snippet extraction.
type FileMap map[string]string

// langExtensions maps file extensions to language names.
var langExtensions = map[string]string{
	".go":         "go",
	".py":         "python",
	".ts":         "typescript",
	".tsx":        "typescript",
	".js":         "javascript",
	".jsx":        "javascript",
	".java":       "java",
	".rb":         "ruby",
	".rs":         "rust",
	".c":          "c",
	".h":          "c",
	".cpp":        "cpp",
	".cc":         "cpp",
	".hpp":        "cpp",
	".cs":         "csharp",
	".swift":      "swift",
	".kt":         "kotlin",
	".kts":        "kotlin",
	".scala":      "scala",
	".php":        "php",
	".sh":         "shell",
	".bash":       "shell",
	".zsh":        "shell",
	".yaml":       "yaml",
	".yml":        "yaml",
	".json":       "json",
	".xml":        "xml",
	".html":       "html",
	".htm":        "html",
	".css":        "css",
	".scss":       "scss",
	".sql":        "sql",
	".proto":      "protobuf",
	".r":          "r",
	".R":          "r",
	".pl":         "perl",
	".pm":         "perl",
	".lua":        "lua",
	".dart":       "dart",
	".tf":         "terraform",
	".hcl":        "hcl",
	".md":         "markdown",
	".toml":       "toml",
	".ini":        "ini",
	".cfg":        "ini",
	".dockerfile": "dockerfile",
	".ex":         "elixir",
	".exs":        "elixir",
	".erl":        "erlang",
	".hs":         "haskell",
	".ml":         "ocaml",
	".vue":        "vue",
	".svelte":     "svelte",
}

// InferLanguage returns the language name for a given file path based on extension.
// Returns empty string for unrecognized extensions.
func InferLanguage(path string) string {
	// Handle Dockerfile specially (no extension).
	base := filepath.Base(path)
	lower := strings.ToLower(base)
	if lower == "dockerfile" || strings.HasPrefix(lower, "dockerfile.") {
		return "dockerfile"
	}
	if lower == "makefile" || lower == "gnumakefile" {
		return "makefile"
	}

	ext := strings.ToLower(filepath.Ext(path))
	if lang, ok := langExtensions[ext]; ok {
		return lang
	}
	return ""
}

// isBinaryContent checks whether data looks like binary content by searching
// for a null byte in the first 512 bytes.
func isBinaryContent(data []byte) bool {
	limit := 512
	if len(data) < limit {
		limit = len(data)
	}
	return bytes.Contains(data[:limit], []byte{0})
}

// sanitizeUTF8 replaces invalid UTF-8 bytes with the Unicode replacement character.
func sanitizeUTF8(data []byte) string {
	if utf8.Valid(data) {
		return string(data)
	}
	var buf strings.Builder
	buf.Grow(len(data))
	for len(data) > 0 {
		r, size := utf8.DecodeRune(data)
		if r == utf8.RuneError && size <= 1 {
			buf.WriteRune(utf8.RuneError)
			data = data[1:]
		} else {
			buf.WriteRune(r)
			data = data[size:]
		}
	}
	return buf.String()
}

// countLines returns the number of lines in s.
// An empty string has 0 lines, a string with no newline has 1 line.
func countLines(s string) int {
	if s == "" {
		return 0
	}
	n := strings.Count(s, "\n")
	if !strings.HasSuffix(s, "\n") {
		n++
	}
	return n
}

// gitignoreStack tracks a stack of compiled .gitignore matchers for nested
// .gitignore support. Each entry is associated with the directory depth at which
// the .gitignore was found.
type gitignoreStack struct {
	entries []gitignoreEntry
}

type gitignoreEntry struct {
	matcher *ignore.GitIgnore
	depth   int
}

func (s *gitignoreStack) push(matcher *ignore.GitIgnore, depth int) {
	s.entries = append(s.entries, gitignoreEntry{matcher: matcher, depth: depth})
}

// popAbove removes matchers that were added at a depth greater than the given depth.
func (s *gitignoreStack) popAbove(depth int) {
	for len(s.entries) > 0 && s.entries[len(s.entries)-1].depth > depth {
		s.entries = s.entries[:len(s.entries)-1]
	}
}

// isIgnored checks whether the given relative path is matched by any active
// .gitignore in the stack. Paths are checked against all active matchers.
func (s *gitignoreStack) isIgnored(relPath string, isDir bool) bool {
	pathToCheck := relPath
	if isDir {
		pathToCheck = relPath + "/"
	}
	for _, entry := range s.entries {
		if entry.matcher.MatchesPath(pathToCheck) {
			return true
		}
	}
	return false
}

// WalkDir recursively walks the directory tree rooted at root, returning all
// source files that are not ignored by .gitignore, not symlinks, and not binary.
// Permission errors are logged as warnings but do not halt the walk.
func WalkDir(root string) ([]SourceFile, error) {
	root, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}

	// Verify the root directory exists.
	info, err := os.Stat(root)
	if err != nil {
		return nil, fmt.Errorf("cannot access root directory: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("root path is not a directory: %s", root)
	}

	var files []SourceFile
	stack := &gitignoreStack{}

	// Load root .gitignore if present.
	rootGitignore := filepath.Join(root, ".gitignore")
	if gi, err := ignore.CompileIgnoreFile(rootGitignore); err == nil {
		stack.push(gi, 0)
	}

	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			slog.Warn("permission error, skipping", "path", path, "error", err)
			return nil
		}

		// filepath.Rel cannot fail here since both root and path are absolute,
		// but propagate the error to avoid silent corruption if assumptions change.
		relPath, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return relErr
		}

		// Skip the root directory itself.
		if relPath == "." {
			return nil
		}

		depth := strings.Count(relPath, string(filepath.Separator))

		// Pop gitignore entries from deeper directories we've left.
		stack.popAbove(depth)

		// Skip .git directory.
		if d.IsDir() && d.Name() == ".git" {
			return fs.SkipDir
		}

		// Check symlinks via Lstat.
		info, lstatErr := os.Lstat(path)
		if lstatErr != nil {
			slog.Warn("cannot stat file, skipping", "path", relPath, "error", lstatErr)
			return nil
		}
		if info.Mode()&os.ModeSymlink != 0 {
			slog.Debug("skipping symlink", "path", relPath)
			if info.IsDir() {
				return fs.SkipDir
			}
			return nil
		}

		// Check gitignore patterns.
		if stack.isIgnored(relPath, d.IsDir()) {
			slog.Debug("ignored by .gitignore", "path", relPath)
			if d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}

		// For directories, check for nested .gitignore.
		if d.IsDir() {
			nestedGitignore := filepath.Join(path, ".gitignore")
			if gi, loadErr := ignore.CompileIgnoreFile(nestedGitignore); loadErr == nil {
				stack.push(gi, depth+1)
			}
			return nil
		}

		// Skip .gitignore files — they are metadata, not source.
		if d.Name() == ".gitignore" {
			return nil
		}

		// Read file content.
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			slog.Warn("cannot read file, skipping", "path", relPath, "error", readErr)
			return nil
		}

		// Skip binary files.
		if isBinaryContent(data) {
			slog.Debug("skipping binary file", "path", relPath)
			return nil
		}

		// Sanitize UTF-8.
		content := sanitizeUTF8(data)

		files = append(files, SourceFile{
			Path:      relPath,
			Content:   content,
			LineCount: countLines(content),
			Language:  InferLanguage(relPath),
		})

		return nil
	})

	if err != nil {
		return nil, err
	}

	return files, nil
}
