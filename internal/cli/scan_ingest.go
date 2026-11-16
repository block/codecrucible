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
