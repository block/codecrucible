package ingest

import (
	"log/slog"
	"path/filepath"
	"strings"
)

// DefaultMaxFileSize is the default maximum file size in bytes (100KB).
// Most application source files are well under this; files exceeding it are
// typically generated code, fixtures, or data files that waste token budget.
const DefaultMaxFileSize = 100 * 1024

// FilterConfig controls which files are kept or excluded by FilterFiles.
type FilterConfig struct {
	IncludeTests bool     // When true, test files are not excluded.
	IncludeDocs  bool     // When true, .md files are not excluded.
	Include      []string // Custom glob patterns to force-include.
	Exclude      []string // Custom glob patterns to additionally exclude.
	MaxFileSize  int      // Maximum file size in bytes (0 = no limit).
}

// FilterStats reports how many files were excluded per category.
type FilterStats struct {
	Tests     int
	Vendor    int
	Binary    int
	Docs      int
	Custom    int
	LowValue  int
	Oversized int
	Kept      int
	Total     int
}

// testFilePatterns matches individual test file naming conventions.
var testFilePatterns = []string{
	"*_test.go",
	"test_*.py",
	"*_spec.ts",
	"*_spec.js",
	"*_spec.tsx",
	"*_spec.jsx",
	"*_test.py",
	"*_test.ts",
	"*_test.js",
	"test_*.go",
	"test_*.ts",
	"test_*.js",
}

// testDirNames are directory names that indicate test content.
var testDirNames = map[string]bool{
	"test":      true,
	"tests":     true,
	"__tests__": true,
	"spec":      true,
	"__mocks__": true,
}

// vendorDirNames are directory names that indicate vendored dependencies.
var vendorDirNames = map[string]bool{
	"vendor":       true,
	"node_modules": true,
	"__pycache__":  true,
	".venv":        true,
	"venv":         true,
}

// lowValueDirNames are directories containing CI/CD, tooling, or data files
// that produce noisy, low-value security findings and dilute LLM analysis.
var lowValueDirNames = map[string]bool{
	".github":        true,
	".circleci":      true,
	".dependabot":    true,
	".gitlab":        true,
	".husky":         true,
	".vscode":        true,
	".idea":          true,
	".zap":           true,
	"encryptionkeys": true,
}

// lowValueExtensions are file extensions unlikely to contain exploitable vulnerabilities.
var lowValueExtensions = map[string]bool{
	".key":   true,
	".pem":   true,
	".crt":   true,
	".pub":   true,
	".cert":  true,
	".tsv":   true,
	".csv":   true,
	".ipynb": true,
}

// lowValueFilenames are specific filenames that are build/config artifacts.
var lowValueFilenames = map[string]bool{
	"Gruntfile.js":       true,
	"Gulpfile.js":        true,
	"Cakefile":           true,
	"Rakefile":           true,
	"ctf.key":            true,
	".npmrc":             true,
	".eslintrc.js":       true,
	".eslintrc.json":     true,
	".prettierrc":        true,
	".prettierrc.json":   true,
	".babelrc":           true,
	"jest.config.js":     true,
	"jest.config.ts":     true,
	"karma.conf.js":      true,
	"protractor.conf.js": true,
	"package-lock.json":  true,
	"yarn.lock":          true,
	"pnpm-lock.yaml":     true,
	"composer.lock":      true,
	"Gemfile.lock":       true,
	"Pipfile.lock":       true,
	"poetry.lock":        true,
	"Cargo.lock":         true,
}

// binaryExtensions are file extensions that indicate binary/generated content.
var binaryExtensions = map[string]bool{
	".exe":    true,
	".dll":    true,
	".so":     true,
	".dylib":  true,
	".a":      true,
	".o":      true,
	".obj":    true,
	".lib":    true,
	".png":    true,
	".jpg":    true,
	".jpeg":   true,
	".gif":    true,
	".bmp":    true,
	".ico":    true,
	".svg":    true,
	".webp":   true,
	".zip":    true,
	".tar":    true,
	".gz":     true,
	".bz2":    true,
	".xz":     true,
	".7z":     true,
	".rar":    true,
	".jar":    true,
	".war":    true,
	".class":  true,
	".pyc":    true,
	".pyo":    true,
	".wasm":   true,
	".pdf":    true,
	".doc":    true,
	".docx":   true,
	".xls":    true,
	".xlsx":   true,
	".ppt":    true,
	".pptx":   true,
	".ttf":    true,
	".otf":    true,
	".woff":   true,
	".woff2":  true,
	".eot":    true,
	".mp3":    true,
	".mp4":    true,
	".wav":    true,
	".avi":    true,
	".mov":    true,
	".db":     true,
	".sqlite": true,
}

// alwaysIncludeExtensions are extensions that should never be filtered out,
// regardless of their location (e.g., even inside test directories).
var alwaysIncludeExtensions = map[string]bool{
	".proto":   true,
	".sql":     true,
	".graphql": true,
	".gql":     true,
}

// FilterFiles applies heuristic filters to a list of source files and returns
// the files that pass all filters. It logs summary statistics about excluded files.
func FilterFiles(files []SourceFile, cfg FilterConfig) ([]SourceFile, FilterStats) {
	var stats FilterStats
	stats.Total = len(files)

	if len(files) == 0 {
		return []SourceFile{}, stats
	}

	var kept []SourceFile

	for _, f := range files {
		category := classifyFile(f, cfg)
		switch category {
		case categoryKept:
			kept = append(kept, f)
			stats.Kept++
		case categoryTest:
			stats.Tests++
		case categoryVendor:
			stats.Vendor++
		case categoryBinary:
			stats.Binary++
		case categoryDocs:
			stats.Docs++
		case categoryCustom:
			stats.Custom++
		case categoryLowValue:
			stats.LowValue++
		case categoryOversized:
			stats.Oversized++
		}
	}

	if kept == nil {
		kept = []SourceFile{}
	}

	logFilterStats(stats)
	return kept, stats
}

// fileCategory represents why a file was kept or excluded.
type fileCategory int

const (
	categoryKept fileCategory = iota
	categoryTest
	categoryVendor
	categoryBinary
	categoryDocs
	categoryCustom
	categoryLowValue
	categoryOversized
)

// classifyFile determines whether a file should be kept or excluded, and why.
func classifyFile(f SourceFile, cfg FilterConfig) fileCategory {
	ext := strings.ToLower(filepath.Ext(f.Path))

	// Always-include extensions bypass all filters.
	if alwaysIncludeExtensions[ext] {
		return categoryKept
	}

	// Custom include patterns: if any match, the file is force-included.
	if matchesAnyGlob(f.Path, cfg.Include) {
		return categoryKept
	}

	// Custom exclude patterns: checked before default heuristics.
	if matchesAnyGlob(f.Path, cfg.Exclude) {
		return categoryCustom
	}

	// Oversized file check.
	if cfg.MaxFileSize > 0 && len(f.Content) > cfg.MaxFileSize {
		return categoryOversized
	}

	// Binary extension check.
	if binaryExtensions[ext] {
		return categoryBinary
	}

	// Binary content check (null byte in first 512 bytes).
	if isBinaryFile(f.Content) {
		return categoryBinary
	}

	// Vendor directory check.
	if isInVendorDir(f.Path) {
		return categoryVendor
	}

	// Low-value file check (CI/CD, tooling, key files).
	if isLowValueFile(f.Path) {
		return categoryLowValue
	}

	// Test file/directory check (skipped if IncludeTests is set).
	if !cfg.IncludeTests && isTestFile(f.Path) {
		return categoryTest
	}

	// Documentation check (skipped if IncludeDocs is set).
	if !cfg.IncludeDocs && ext == ".md" {
		return categoryDocs
	}

	return categoryKept
}

// isTestFile checks whether a file path looks like a test file,
// either by filename pattern or by being inside a test directory.
func isTestFile(path string) bool {
	base := filepath.Base(path)

	// Check filename patterns.
	for _, pattern := range testFilePatterns {
		if matched, _ := filepath.Match(pattern, base); matched {
			return true
		}
	}

	// Check if any path component is a test directory.
	parts := strings.Split(filepath.ToSlash(path), "/")
	for _, part := range parts {
		if testDirNames[part] {
			return true
		}
	}

	return false
}

// isInVendorDir checks whether a file is inside a vendor directory.
func isInVendorDir(path string) bool {
	parts := strings.Split(filepath.ToSlash(path), "/")
	for _, part := range parts {
		if vendorDirNames[part] {
			return true
		}
	}
	return false
}

// isBinaryFile checks file content for null bytes in the first 512 bytes.
func isBinaryFile(content string) bool {
	limit := 512
	if len(content) < limit {
		limit = len(content)
	}
	return strings.Contains(content[:limit], "\x00")
}

// matchesAnyGlob returns true if path matches any of the given glob patterns.
// Patterns are matched against the full relative path and also against just
// the filename component.
func matchesAnyGlob(path string, patterns []string) bool {
	if len(patterns) == 0 {
		return false
	}

	// Normalize to forward slashes for consistent matching.
	normalized := filepath.ToSlash(path)
	base := filepath.Base(path)

	for _, pattern := range patterns {
		pattern = filepath.ToSlash(pattern)

		if pattern == "**" {
			return true
		}

		// Match against full path.
		if matched, _ := filepath.Match(pattern, normalized); matched {
			return true
		}

		// Match against base filename.
		if matched, _ := filepath.Match(pattern, base); matched {
			return true
		}

		// Support ** prefix patterns by checking if path ends with pattern suffix.
		if strings.HasPrefix(pattern, "**/") {
			suffix := pattern[3:]
			// Check if any path suffix matches.
			if matched, _ := filepath.Match(suffix, base); matched {
				return true
			}
			// Check path segments.
			parts := strings.Split(normalized, "/")
			for i := range parts {
				subpath := strings.Join(parts[i:], "/")
				if matched, _ := filepath.Match(suffix, subpath); matched {
					return true
				}
			}
		}

		// Support trailing /** patterns as recursive directory matches,
		// e.g. firmware/third-party/** should match all descendants.
		if strings.HasSuffix(pattern, "/**") {
			dirPattern := strings.TrimSuffix(pattern, "/**")

			// Check the full path and every ancestor directory against
			// the directory pattern, so wildcard segments still work.
			if matched, _ := filepath.Match(dirPattern, normalized); matched {
				return true
			}
			parts := strings.Split(normalized, "/")
			for i := 1; i < len(parts); i++ {
				ancestor := strings.Join(parts[:i], "/")
				if matched, _ := filepath.Match(dirPattern, ancestor); matched {
					return true
				}
			}
		}
	}

	return false
}

// isLowValueFile checks whether a file is in a low-value directory, has a
// low-value extension, or has a low-value filename (CI/CD, tooling, key files).
func isLowValueFile(path string) bool {
	base := filepath.Base(path)
	ext := strings.ToLower(filepath.Ext(path))

	// Check filename
	if lowValueFilenames[base] {
		return true
	}

	// Check extension
	if lowValueExtensions[ext] {
		return true
	}

	// Check if any path component is a low-value directory
	parts := strings.Split(filepath.ToSlash(path), "/")
	for _, part := range parts {
		if lowValueDirNames[part] {
			return true
		}
	}

	return false
}

// logFilterStats logs a summary of filter results.
func logFilterStats(stats FilterStats) {
	excluded := stats.Total - stats.Kept
	if excluded == 0 {
		slog.Info("file filter: all files kept", "total", stats.Total)
		return
	}

	slog.Info("file filter summary",
		"total", stats.Total,
		"kept", stats.Kept,
		"excluded", excluded,
		"tests", stats.Tests,
		"vendor", stats.Vendor,
		"binary", stats.Binary,
		"docs", stats.Docs,
		"custom", stats.Custom,
		"low_value", stats.LowValue,
		"oversized", stats.Oversized,
	)
}
