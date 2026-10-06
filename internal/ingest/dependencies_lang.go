package ingest

import (
	"path"
	"regexp"
	"strings"
)

// sourceIndex locates admitted files by the names other languages import:
// JVM packages, C# and PHP namespaces, PHP classes, and path suffixes.
type sourceIndex struct {
	known      map[string]bool
	dirs       map[string][]string // directory/extension family -> files
	jvm        map[string][]string // package -> files
	csharp     map[string][]string // namespace -> files
	php        map[string][]string // namespace -> files
	phpClasses map[string]string   // fully qualified class -> file
	suffixes   map[string][]string // trailing path segments -> files
}

var (
	jvmPackage   = regexp.MustCompile(`(?m)^\s*package\s+([\w.]+)`)
	jvmImport    = regexp.MustCompile(`(?m)^\s*import\s+(?:static\s+)?([\w.]+(?:\.\*|\._|\.\{[^}\n]*\})?)`)
	csNamespace  = regexp.MustCompile(`(?m)^\s*namespace\s+([\w.]+)`)
	csUsing      = regexp.MustCompile(`(?m)^\s*(?:global\s+)?using\s+(static\s+)?(?:\w+\s*=\s*)?([\w.]+)\s*;`)
	phpNamespace = regexp.MustCompile(`(?m)^\s*namespace\s+([\w\\]+)\s*[;{]`)
	phpClass     = regexp.MustCompile(`(?m)^\s*(?:(?:abstract|final|readonly)\s+)*(?:class|interface|trait|enum)\s+(\w+)`)
	phpUse       = regexp.MustCompile(`(?m)^\s*use\s+(?:function\s+|const\s+)?([\w\\]+)(?:\s*\\\{([^}]*)\}|\s+as\s+\w+)?\s*[;,]`)
	phpRequire   = regexp.MustCompile(`\b(?:require|include)(?:_once)?\s*\(?\s*(__DIR__\s*\.\s*)?['"]([^'"$]+\.php)['"]`)
	jsSpecifier  = regexp.MustCompile(`(?s)\b(?:import|export)\b[^;'"]*?\bfrom\s*['"]([^'"\n]+)['"]|\b(?:require|import)\s*\(\s*['"]([^'"\n]+)['"]\s*\)|(?m:^\s*import\s+['"]([^'"\n]+)['"])`)
	pyFrom       = regexp.MustCompile(`(?m)^\s*from\s+([.\w]+)\s+import\s+(\([^)]*\)|[^\n#;]+)`)
	pyImport     = regexp.MustCompile(`(?m)^\s*import\s+([\w.]+(?:\s*,\s*[\w.]+)*)`)
	rustMod      = regexp.MustCompile(`(?m)^\s*(?:pub(?:\([^)]*\))?\s+)?mod\s+(\w+)\s*;`)
	rustUse      = regexp.MustCompile(`(?m)^\s*(?:pub(?:\([^)]*\))?\s+)?use\s+((?:crate|super|self)::[^;]+);`)
	cInclude     = regexp.MustCompile(`(?m)^\s*#\s*include\s*["<]([^">]+)[">]`)
	rubyRequire  = regexp.MustCompile(`(?m)^\s*require_relative\s*\(?\s*['"]([^'"]+)['"]`)
)

func family(p string) string {
	switch ext := path.Ext(p); ext {
	case ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts":
		return "js"
	case ".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh":
		return "c"
	case ".kt", ".kts":
		return ".kt"
	default:
		return ext
	}
}

func newSourceIndex(files []SourceFile) *sourceIndex {
	idx := &sourceIndex{known: map[string]bool{}, dirs: map[string][]string{}, jvm: map[string][]string{},
		csharp: map[string][]string{}, php: map[string][]string{}, phpClasses: map[string]string{}, suffixes: map[string][]string{}}
	for _, f := range files {
		idx.known[f.Path] = true
		idx.dirs[path.Dir(f.Path)+"|"+family(f.Path)] = append(idx.dirs[path.Dir(f.Path)+"|"+family(f.Path)], f.Path)
		parts := strings.Split(f.Path, "/")
		for k := 1; k < len(parts); k++ {
			suffix := strings.Join(parts[k:], "/")
			idx.suffixes[suffix] = append(idx.suffixes[suffix], f.Path)
		}
		switch family(f.Path) {
		case ".java", ".kt", ".scala":
			if m := jvmPackage.FindStringSubmatch(f.Content); m != nil {
				idx.jvm[m[1]] = append(idx.jvm[m[1]], f.Path)
			}
		case ".cs":
			for _, m := range csNamespace.FindAllStringSubmatch(f.Content, -1) {
				idx.csharp[m[1]] = append(idx.csharp[m[1]], f.Path)
			}
		case ".php":
			namespace := ""
			if m := phpNamespace.FindStringSubmatch(f.Content); m != nil {
				namespace = m[1]
				idx.php[namespace] = append(idx.php[namespace], f.Path)
			}
			for _, m := range phpClass.FindAllStringSubmatch(f.Content, -1) {
				idx.phpClasses[strings.TrimPrefix(namespace+`\`+m[1], `\`)] = f.Path
			}
		}
	}
	return idx
}

// languageDependencies returns best-effort local edges for languages beyond
// Go. Candidates outside the admitted file set are dropped by the caller.
func (idx *sourceIndex) languageDependencies(f SourceFile) []string {
	dir := path.Dir(f.Path)
	switch family(f.Path) {
	case "js":
		return idx.jsDependencies(f, dir)
	case ".py":
		return idx.pythonDependencies(f, dir)
	case ".java", ".kt", ".scala":
		return idx.jvmDependencies(f)
	case ".cs":
		return idx.csharpDependencies(f)
	case ".php":
		return idx.phpDependencies(f, dir)
	case ".rs":
		return idx.rustDependencies(f, dir)
	case "c":
		return idx.cDependencies(f, dir)
	case ".swift":
		// Files of one module directory share declarations without imports.
		return idx.dirs[dir+"|.swift"]
	case ".rb":
		var out []string
		for _, m := range rubyRequire.FindAllStringSubmatch(f.Content, -1) {
			out = append(out, strings.TrimSuffix(path.Join(dir, m[1]), ".rb")+".rb")
		}
		return out
	}
	return nil
}

var jsCandidates = []string{".ts", ".tsx", ".mts", ".cts", ".js", ".jsx", ".mjs", ".cjs"}

func (idx *sourceIndex) jsDependencies(f SourceFile, dir string) []string {
	var out []string
	for _, m := range jsSpecifier.FindAllStringSubmatch(f.Content, -1) {
		spec := m[1] + m[2] + m[3]
		var bases []string
		switch {
		case strings.HasPrefix(spec, "./") || strings.HasPrefix(spec, "../"):
			bases = []string{path.Join(dir, spec)}
		case strings.HasPrefix(spec, "@/") || strings.HasPrefix(spec, "~/"):
			// Conventional tsconfig aliases point at the project root or src/.
			rest := spec[2:]
			for d := dir; ; d = path.Dir(d) {
				bases = append(bases, path.Join(d, rest), path.Join(d, "src", rest))
				if d == "." || d == "/" {
					break
				}
			}
		default:
			continue
		}
		for _, base := range bases {
			ext := path.Ext(base)
			stem := strings.TrimSuffix(base, ext)
			switch ext {
			case ".js", ".jsx", ".mjs", ".cjs":
				// TypeScript imports compiled names: './x.js' resolves to x.ts.
				out = append(out, base, stem+".ts", stem+".tsx", stem+".mts", stem+".cts")
			case "":
			default:
				out = append(out, base)
				continue
			}
			for _, e := range jsCandidates {
				out = append(out, base+e, base+"/index"+e)
			}
		}
	}
	return out
}

func (idx *sourceIndex) pythonModule(module string) []string {
	parts := strings.Split(module, ".")
	candidates := []string{path.Join(parts...) + ".py", path.Join(append(parts, "__init__.py")...)}
	out := []string{}
	for _, c := range candidates {
		if idx.known[c] {
			out = append(out, c)
		} else if len(parts) >= 2 {
			// src/ layouts and nested roots: match the dotted path as a suffix.
			out = append(out, idx.suffixes[c]...)
		}
	}
	return out
}

func (idx *sourceIndex) pythonDependencies(f SourceFile, dir string) []string {
	var out []string
	for _, m := range pyImport.FindAllStringSubmatch(f.Content, -1) {
		for _, module := range strings.Split(m[1], ",") {
			out = append(out, idx.pythonModule(strings.TrimSpace(module))...)
		}
	}
	for _, m := range pyFrom.FindAllStringSubmatch(f.Content, -1) {
		module := m[1]
		var names []string
		for _, name := range strings.FieldsFunc(strings.Trim(m[2], "() \t\r\n\\"), func(r rune) bool { return r == ',' || r == '\n' }) {
			if fields := strings.Fields(name); len(fields) > 0 && fields[0] != "*" {
				names = append(names, fields[0])
			}
		}
		if strings.HasPrefix(module, ".") {
			// Relative modules resolve in ResolveImports; add imported submodules.
			dots := len(module) - len(strings.TrimLeft(module, "."))
			base := dir
			for i := 1; i < dots; i++ {
				base = path.Dir(base)
			}
			if rest := module[dots:]; rest != "" {
				base = path.Join(append([]string{base}, strings.Split(rest, ".")...)...)
			}
			for _, name := range names {
				out = append(out, path.Join(base, name)+".py", path.Join(base, name, "__init__.py"))
			}
			continue
		}
		out = append(out, idx.pythonModule(module)...)
		for _, name := range names {
			out = append(out, idx.pythonModule(module+"."+name)...)
		}
	}
	return out
}

func (idx *sourceIndex) jvmDependencies(f SourceFile) []string {
	var out []string
	if m := jvmPackage.FindStringSubmatch(f.Content); m != nil {
		out = append(out, idx.jvm[m[1]]...)
	}
	for _, m := range jvmImport.FindAllStringSubmatch(f.Content, -1) {
		spec := m[1]
		var names []string
		if i := strings.Index(spec, ".{"); i >= 0 {
			for _, name := range strings.Split(strings.Trim(spec[i+2:], "}"), ",") {
				names = append(names, strings.TrimSpace(strings.Split(name, "=>")[0]))
			}
			spec = spec[:i]
		} else if strings.HasSuffix(spec, ".*") || strings.HasSuffix(spec, "._") {
			out = append(out, idx.jvm[spec[:len(spec)-2]]...)
			continue
		} else {
			i := strings.LastIndex(spec, ".")
			if i < 0 {
				continue
			}
			spec, names = spec[:i], []string{spec[i+1:]}
		}
		// Static and nested imports name members of a class: walk up to the
		// longest declared package.
		for pkg := spec; pkg != ""; {
			if files, ok := idx.jvm[pkg]; ok {
				matched := false
				for _, file := range files {
					stem := strings.TrimSuffix(path.Base(file), path.Ext(file))
					for _, name := range append(names, strings.TrimPrefix(spec, pkg+".")) {
						if first := strings.Split(name, ".")[0]; first == stem {
							out = append(out, file)
							matched = true
						}
					}
				}
				if !matched {
					out = append(out, files...) // Kotlin top-level functions
				}
				break
			}
			i := strings.LastIndex(pkg, ".")
			if i < 0 {
				break
			}
			names = []string{pkg[i+1:]}
			pkg = pkg[:i]
		}
	}
	return out
}

func (idx *sourceIndex) csharpDependencies(f SourceFile) []string {
	var out []string
	for _, m := range csNamespace.FindAllStringSubmatch(f.Content, -1) {
		out = append(out, idx.csharp[m[1]]...)
	}
	for _, m := range csUsing.FindAllStringSubmatch(f.Content, -1) {
		name := m[2]
		if m[1] == "" {
			out = append(out, idx.csharp[name]...)
			continue
		}
		if i := strings.LastIndex(name, "."); i >= 0 {
			for _, file := range idx.csharp[name[:i]] {
				if strings.TrimSuffix(path.Base(file), ".cs") == name[i+1:] {
					out = append(out, file)
				}
			}
		}
	}
	return out
}

func (idx *sourceIndex) phpDependencies(f SourceFile, dir string) []string {
	var out []string
	if m := phpNamespace.FindStringSubmatch(f.Content); m != nil {
		out = append(out, idx.php[m[1]]...)
	}
	resolve := func(name string) {
		name = strings.Trim(strings.TrimSpace(name), `\`)
		if file, ok := idx.phpClasses[name]; ok {
			out = append(out, file)
		} else if files, ok := idx.php[name]; ok {
			out = append(out, files...)
		}
	}
	for _, m := range phpUse.FindAllStringSubmatch(f.Content, -1) {
		if m[2] == "" {
			resolve(m[1])
			continue
		}
		for _, name := range strings.Split(m[2], ",") {
			resolve(m[1] + `\` + strings.Fields(name + " ")[0])
		}
	}
	for _, m := range phpRequire.FindAllStringSubmatch(f.Content, -1) {
		target := strings.TrimPrefix(m[2], "/")
		if m[1] != "" || strings.HasPrefix(m[2], ".") {
			target = path.Join(dir, m[2])
		}
		out = append(out, target, path.Join(dir, m[2]))
	}
	return out
}

// rustModuleDir is where a file's child modules live: src/a.rs -> src/a.
func rustModuleDir(file string) string {
	switch base := path.Base(file); base {
	case "mod.rs", "lib.rs", "main.rs":
		return path.Dir(file)
	default:
		return strings.TrimSuffix(file, ".rs")
	}
}

func (idx *sourceIndex) rustModule(dir string, segments []string) []string {
	// The longest module path wins; trailing segments name items.
	for n := len(segments); n > 0; n-- {
		base := path.Join(append([]string{dir}, segments[:n]...)...)
		for _, c := range []string{base + ".rs", base + "/mod.rs"} {
			if idx.known[c] {
				return []string{c}
			}
		}
	}
	return nil
}

func expandRustUse(spec string) []string {
	spec = strings.Join(strings.Fields(spec), "")
	open := strings.Index(spec, "{")
	if open < 0 {
		return []string{spec}
	}
	depth, start := 0, open+1
	var out []string
	for i := open; i < len(spec); i++ {
		switch spec[i] {
		case '{':
			depth++
		case '}', ',':
			if spec[i] == '}' {
				depth--
			}
			if depth == 1 && spec[i] == ',' || depth == 0 {
				for _, item := range expandRustUse(spec[start:i]) {
					out = append(out, spec[:open]+item)
				}
				start = i + 1
			}
			if depth == 0 {
				return out
			}
		}
	}
	return out
}

func (idx *sourceIndex) rustDependencies(f SourceFile, dir string) []string {
	var out []string
	moduleDir := rustModuleDir(f.Path)
	for _, m := range rustMod.FindAllStringSubmatch(f.Content, -1) {
		out = append(out, path.Join(moduleDir, m[1]+".rs"), path.Join(moduleDir, m[1], "mod.rs"))
	}
	root := ""
	for d := dir; ; d = path.Dir(d) {
		if idx.known[path.Join(d, "lib.rs")] || idx.known[path.Join(d, "main.rs")] {
			root = d
			break
		}
		if d == "." || d == "/" {
			break
		}
	}
	for _, m := range rustUse.FindAllStringSubmatch(f.Content, -1) {
		for _, spec := range expandRustUse(m[1]) {
			segments := strings.Split(spec, "::")
			base := ""
			switch segments[0] {
			case "crate":
				base = root
				if root == "" {
					continue
				}
			case "self":
				base = moduleDir
			case "super":
				base = path.Dir(moduleDir)
			}
			segments = segments[1:]
			for len(segments) > 0 && segments[0] == "super" {
				base, segments = path.Dir(base), segments[1:]
			}
			if len(segments) == 0 || segments[0] == "" || segments[0] == "*" {
				continue
			}
			out = append(out, idx.rustModule(base, segments)...)
		}
	}
	return out
}

func (idx *sourceIndex) cDependencies(f SourceFile, dir string) []string {
	var out []string
	stem := strings.TrimSuffix(f.Path, path.Ext(f.Path))
	for _, ext := range []string{".h", ".hpp", ".hh", ".c", ".cc", ".cpp", ".cxx"} {
		out = append(out, stem+ext) // implementation and header pairs
	}
	for _, m := range cInclude.FindAllStringSubmatch(f.Content, -1) {
		local := path.Join(dir, m[1])
		if idx.known[local] {
			out = append(out, local)
			continue
		}
		// Include roots are build configuration; a unique suffix is safe.
		if matches := idx.suffixes[path.Clean(m[1])]; len(matches) == 1 {
			out = append(out, matches...)
		}
	}
	return out
}
