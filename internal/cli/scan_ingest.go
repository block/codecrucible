package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/block/codecrucible/internal/config"
	"github.com/block/codecrucible/internal/ingest"
)

// ingestFiles walks the repo and optionally restricts to --paths.
func ingestFiles(repoRoot string, cfg *config.Config) ([]ingest.SourceFile, error) {
	// Always walk from repo root so .gitignore behavior is consistent whether
	// or not --paths is provided.
	files, err := ingest.WalkDir(repoRoot)
	if err != nil {
		return nil, err
	}

	if len(cfg.Paths) == 0 {
		return files, nil
	}

	normalizedPaths, err := normalizeScanPaths(repoRoot, cfg.Paths)
	if err != nil {
		return nil, err
	}

	filtered := make([]ingest.SourceFile, 0, len(files))
	for _, f := range files {
		if pathMatchesAnyPrefix(f.Path, normalizedPaths) {
			filtered = append(filtered, f)
		}
	}

	return filtered, nil
}

// normalizeScanPaths validates and normalizes --paths values to repo-relative,
// slash-separated prefixes.
func normalizeScanPaths(repoRoot string, paths []string) ([]string, error) {
	normalized := make([]string, 0, len(paths))
	seen := make(map[string]struct{}, len(paths))

	for _, p := range paths {
		absPath := filepath.Clean(filepath.Join(repoRoot, p))

		relPath, err := filepath.Rel(repoRoot, absPath)
		if err != nil {
			return nil, fmt.Errorf("walking path %s: %w", p, err)
		}
		if relPath == ".." || strings.HasPrefix(relPath, ".."+string(filepath.Separator)) {
			return nil, fmt.Errorf("walking path %s: path escapes repository root", p)
		}

		info, err := os.Stat(absPath)
		if err != nil {
			return nil, fmt.Errorf("walking path %s: %w", p, err)
		}
		if !info.IsDir() {
			return nil, fmt.Errorf("walking path %s: root path is not a directory: %s", p, absPath)
		}

		normalizedPath := filepath.ToSlash(filepath.Clean(relPath))
		if normalizedPath == "." {
			return []string{"."}, nil
		}

		if _, ok := seen[normalizedPath]; ok {
			continue
		}
		seen[normalizedPath] = struct{}{}
		normalized = append(normalized, normalizedPath)
	}

	return normalized, nil
}

// pathMatchesAnyPrefix reports whether path is equal to, or nested under, one
// of the provided repo-relative path prefixes.
func pathMatchesAnyPrefix(path string, prefixes []string) bool {
	normalizedPath := filepath.ToSlash(filepath.Clean(path))

	for _, prefix := range prefixes {
		if prefix == "." {
			return true
		}
		if normalizedPath == prefix || strings.HasPrefix(normalizedPath, prefix+"/") {
			return true
		}
	}

	return false
}

// buildExportSummaries generates one-line summaries of each file's exports/purpose
// using heuristic parsing. Used for cross-chunk context.
func buildExportSummaries(files []ingest.SourceFile) map[string]string {
	summaries := make(map[string]string)
	for _, f := range files {
		summary := summarizeFile(f)
		if summary != "" {
			summaries[f.Path] = summary
		}
	}
	return summaries
}

// summarizeFile produces a one-line heuristic summary of a file's exports.
func summarizeFile(f ingest.SourceFile) string {
	lines := strings.Split(f.Content, "\n")
	var exports []string

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		// JS/TS exports
		if strings.HasPrefix(trimmed, "export ") {
			if strings.Contains(trimmed, "function ") || strings.Contains(trimmed, "const ") ||
				strings.Contains(trimmed, "class ") || strings.Contains(trimmed, "interface ") ||
				strings.Contains(trimmed, "type ") || strings.Contains(trimmed, "default ") {
				// Extract the name
				name := extractExportName(trimmed)
				if name != "" {
					exports = append(exports, name)
				}
			}
		}

		// Go exported functions/types
		if f.Language == "go" {
			if strings.HasPrefix(trimmed, "func ") {
				name := extractGoFuncName(trimmed)
				if name != "" && name[0] >= 'A' && name[0] <= 'Z' {
					exports = append(exports, name+"()")
				}
			} else if strings.HasPrefix(trimmed, "type ") && (strings.Contains(trimmed, " struct") || strings.Contains(trimmed, " interface")) {
				parts := strings.Fields(trimmed)
				if len(parts) >= 2 && parts[1][0] >= 'A' && parts[1][0] <= 'Z' {
					exports = append(exports, parts[1])
				}
			}
		}

		// Python: def and class at module level (no indentation)
		if f.Language == "python" && !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t") {
			if strings.HasPrefix(trimmed, "def ") || strings.HasPrefix(trimmed, "class ") {
				name := extractPyName(trimmed)
				if name != "" && !strings.HasPrefix(name, "_") {
					exports = append(exports, name)
				}
			}
		}

		if len(exports) >= 8 {
			break
		}
	}

	if len(exports) == 0 {
		return ""
	}
	return strings.Join(exports, ", ")
}

func extractExportName(line string) string {
	// "export function foo(" → "foo()"
	// "export const bar =" → "bar"
	// "export class Baz" → "Baz"
	for _, keyword := range []string{"function ", "const ", "let ", "var ", "class ", "interface ", "type ", "default "} {
		idx := strings.Index(line, keyword)
		if idx < 0 {
			continue
		}
		rest := line[idx+len(keyword):]
		rest = strings.TrimSpace(rest)
		// Take until space, paren, equals, or brace.
		end := strings.IndexAny(rest, " (={<:")
		if end > 0 {
			name := rest[:end]
			if keyword == "function " {
				return name + "()"
			}
			return name
		}
		if len(rest) > 0 {
			return rest
		}
	}
	return ""
}

func extractGoFuncName(line string) string {
	// "func FooBar(" → "FooBar"
	// "func (s *Server) Handle(" → "Handle"
	rest := strings.TrimPrefix(line, "func ")
	if strings.HasPrefix(rest, "(") {
		// Method: skip receiver.
		closeIdx := strings.Index(rest, ")")
		if closeIdx < 0 {
			return ""
		}
		rest = strings.TrimSpace(rest[closeIdx+1:])
	}
	end := strings.IndexByte(rest, '(')
	if end > 0 {
		return rest[:end]
	}
	return ""
}

func extractPyName(line string) string {
	// "def foo(..." → "foo"
	// "class Bar:" → "Bar"
	for _, prefix := range []string{"def ", "class "} {
		if strings.HasPrefix(line, prefix) {
			rest := strings.TrimPrefix(line, prefix)
			end := strings.IndexAny(rest, "(: ")
			if end > 0 {
				return rest[:end]
			}
		}
	}
	return ""
}
