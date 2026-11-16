package sourceindex

import (
	"fmt"
	"strings"
)

// FileEntry represents a file with its path and content for feature sample building.
type FileEntry struct {
	Path    string
	Content string
}

// BuildFeatureSamples selects a representative subset of files to include as samples
// for feature detection. It prioritizes dependency manifests and entrypoint files,
// and caps total output at roughly maxTokens * 4 characters.
func BuildFeatureSamples(files []FileEntry, maxTokens int) string {
	return buildFeatureSamples(files, nil, maxTokens)
}

func buildFeatureSamples(files, additional []FileEntry, maxTokens int) string {
	maxChars := maxTokens * 4

	// Dependency manifest filenames to always include.
	manifests := map[string]bool{
		"package.json":     true,
		"go.mod":           true,
		"go.sum":           false, // skip, too large and not informative
		"requirements.txt": true,
		"Cargo.toml":       true,
		"Gemfile":          true,
		"pom.xml":          true,
		"build.gradle":     true,
		"composer.json":    true,
		"pyproject.toml":   true,
		"setup.py":         true,
		"Pipfile":          true,
		"pubspec.yaml":     true,
		"Package.swift":    true,
		"mix.exs":          true,
		"project.clj":      true,
	}

	var out strings.Builder
	written := 0
	included := map[string]bool{}

	addFile := func(path, content string, maxLines int) bool {
		if included[path] {
			return true
		}
		if written >= maxChars {
			return false
		}
		var trimmed string
		if maxLines > 0 {
			lines := strings.SplitN(content, "\n", maxLines+1)
			if len(lines) > maxLines {
				lines = lines[:maxLines]
			}
			trimmed = strings.Join(lines, "\n")
		} else {
			trimmed = content
		}
		entry := fmt.Sprintf("<file path=\"%s\">\n%s\n</file>\n", path, trimmed)
		if written+len(entry) > maxChars {
			remaining := maxChars - written
			if remaining < 100 {
				return false
			}
			entry = entry[:remaining]
		}
		included[path] = true
		out.WriteString(entry)
		written += len(entry)
		return written < maxChars
	}

	// Pass 1: dependency manifests (full content).
	for _, f := range files {
		base := BaseName(f.Path)
		if include, ok := manifests[base]; ok && include {
			if !addFile(f.Path, f.Content, 0) {
				return out.String()
			}
		}
	}

	// Pass 2: entrypoints and routers (first ~50 lines).
	for _, f := range files {
		if IsEntrypoint(f.Path) {
			if !addFile(f.Path, f.Content, 50) {
				return out.String()
			}
		}
	}

	for _, f := range additional {
		if _, manifest := manifests[BaseName(f.Path)]; manifest {
			continue
		}
		if !addFile(f.Path, f.Content, 50) {
			break
		}
	}

	return out.String()
}

// baseName returns the last component of a slash-separated path.
func BaseName(path string) string {
	if i := strings.LastIndex(path, "/"); i >= 0 {
		return path[i+1:]
	}
	return path
}

func IsEntrypoint(path string) bool {
	base := strings.ToLower(BaseName(path))
	lower := strings.ToLower(path)

	entrypointNames := []string{
		"main.go", "main.py", "main.ts", "main.js", "main.rs", "main.rb",
		"server.go", "server.py", "server.ts", "server.js",
		"app.go", "app.py", "app.ts", "app.js", "app.rb",
		"index.ts", "index.js",
	}
	for _, name := range entrypointNames {
		if base == name {
			return true
		}
	}

	routerDirs := []string{"/routes/", "/handlers/", "/controllers/", "/api/", "/middleware/"}
	for _, dir := range routerDirs {
		if strings.Contains(lower, dir) {
			return true
		}
	}

	return false
}

// FeatureSamples uses the same admitted snapshot as chunking and audit.
func (ix *Index) FeatureSamples(maxTokens int) string {
	files := make([]FileEntry, 0, len(ix.paths))
	var additional []FileEntry
	seen := map[string]bool{}
	add := func(p string) {
		if !seen[p] {
			seen[p] = true
			additional = append(additional, FileEntry{p, ix.files[p]})
		}
	}
	for _, p := range ix.paths {
		files = append(files, FileEntry{p, ix.files[p]})
	}
	// A local dependency of an entrypoint is often more informative than the
	// next alphabetically adjacent route. Fill remaining budget with those first.
	for _, p := range ix.paths {
		if IsEntrypoint(p) {
			for _, dep := range ix.graph[p] {
				add(dep)
			}
		}
	}
	// Unknown languages do not need a dedicated entrypoint naming convention.
	// Existing declaration facts provide representative source when available.
	represented := map[string]bool{}
	for _, p := range ix.paths {
		if IsEntrypoint(p) {
			represented[ix.Language(p)] = true
		}
	}
	for _, p := range ix.paths {
		lang := ix.Language(p)
		if !represented[lang] && len(ix.byFile[p]) > 0 {
			add(p)
			represented[lang] = true
		}
	}
	return buildFeatureSamples(files, additional, maxTokens)
}
