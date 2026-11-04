package sourceindex

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

type goAdapter struct{}

var goFallbackFunction = regexp.MustCompile(`^\s*func\s+(?:\([^)]*\)\s*)?([A-Za-z_]\w*)\s*[\[(]`)
var goFallbackType = regexp.MustCompile(`^\s*type\s+([A-Za-z_]\w*)\s+(?:struct|interface)\b`)

func goFallbackDef(line string) (Def, bool) {
	if m := goFallbackFunction.FindStringSubmatch(line); m != nil {
		return Def{Name: m[1]}, true
	}
	if m := goFallbackType.FindStringSubmatch(line); m != nil {
		return Def{Name: m[1], Type: true}, true
	}
	return Def{}, false
}

func (goAdapter) parse(file, text string) *sourceInfo {
	fset := token.NewFileSet()
	root, err := parser.ParseFile(fset, file, text, parser.SkipObjectResolution)
	if err != nil {
		// Broken/incomplete input remains useful lexical context, but cannot
		// supply argument bindings from a partially recovered AST.
		fallback := parseLexical(file, text, goFallbackDef)
		fallback.mode = "fallback"
		fallback.imports, fallback.importPaths = goImports(root)
		if root != nil && root.Name != nil {
			fallback.packageName = root.Name.Name
		}
		return fallback
	}
	s := &sourceInfo{mode: "syntax", adapter: goAdapter{}, language: language(file), packageName: root.Name.Name,
		imports: map[string]string{}, code: strings.Split(maskSource(text, false), "\n")}
	s.imports, s.importPaths = goImports(root)

	pos := func(p token.Pos) int { return fset.Position(p).Offset }
	line := func(p token.Pos) int { return fset.Position(p).Line }
	ast.Inspect(root, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.FuncLit:
			s.unbound = append(s.unbound, [2]int{pos(n.Pos()), pos(n.End())})
		case *ast.FuncDecl:
			d := Def{Name: n.Name.Name, File: file, Line: line(n.Pos()), End: line(n.End())}
			if n.Recv != nil && len(n.Recv.List) == 1 {
				d.owner = goTypeName(n.Recv.List[0].Type)
			}
			for _, field := range n.Type.Params.List {
				if len(field.Names) == 0 {
					d.params = append(d.params, parameter{})
				}
				for _, name := range field.Names {
					d.params = append(d.params, parameter{name.Name, goTypeName(field.Type)})
				}
			}
			if n.Body != nil {
				d.bodyStart, d.bodyEnd = pos(n.Body.Pos()), pos(n.Body.End())
			}
			s.defs = append(s.defs, d)
		case *ast.TypeSpec:
			s.defs = append(s.defs, Def{Name: n.Name.Name, Type: true, File: file, Line: line(n.Pos()), End: line(n.End())})
		case *ast.CallExpr:
			ref := goReference(n.Fun)
			if ref.name == "" {
				break
			}
			ref.offset = pos(n.Pos())
			c := call{reference: ref, start: pos(n.Pos()), end: pos(n.End()), line: line(n.Pos())}
			for _, arg := range n.Args {
				a := argument{start: line(arg.Pos()), end: line(arg.End())}
				if id, ok := arg.(*ast.Ident); ok {
					a.direct = id.Name
				}
				c.args = append(c.args, a)
			}
			s.calls = append(s.calls, c)
		}
		return true
	})
	sort.SliceStable(s.defs, func(i, j int) bool { return s.defs[i].Line < s.defs[j].Line })
	return s
}

func goTypeName(e ast.Expr) string {
	switch e := e.(type) {
	case *ast.Ident:
		return e.Name
	case *ast.StarExpr:
		return goTypeName(e.X)
	case *ast.SelectorExpr:
		return goTypeName(e.X) + "." + e.Sel.Name
	case *ast.IndexExpr:
		return goTypeName(e.X)
	case *ast.IndexListExpr:
		return goTypeName(e.X)
	}
	return ""
}

func goReference(e ast.Expr) reference {
	switch e := e.(type) {
	case *ast.Ident:
		return reference{name: e.Name}
	case *ast.SelectorExpr:
		r := reference{name: e.Sel.Name}
		if id, ok := e.X.(*ast.Ident); ok {
			r.qualifier = id.Name
		}
		return r
	case *ast.IndexExpr:
		return goReference(e.X)
	case *ast.IndexListExpr:
		return goReference(e.X)
	}
	return reference{}
}

func (goAdapter) resolve(ix *Index, file string, ref reference, typ bool) (Def, bool) {
	s := ix.sources[file]
	candidates := ix.candidates(file, ref.name, typ)
	var local []Def
	if imported, ok := s.imports[ref.qualifier]; ok {
		for _, d := range candidates {
			dir := path.Dir(d.File)
			if d.owner == "" && dir != "." && (imported == dir || strings.HasSuffix(imported, "/"+dir)) {
				local = append(local, d)
			}
		}
		return onlyDefinition(local)
	}
	for _, d := range candidates {
		if path.Dir(d.File) == path.Dir(file) && ix.sources[d.File].packageName == s.packageName {
			local = append(local, d)
		}
	}
	if len(local) > 0 {
		return onlyDefinition(local)
	}
	// Receiver types are not inferred across packages without type checking.
	// A unique method name is still a useful retrieval hint, as in a.DB.Query.
	var methods []Def
	for _, d := range candidates {
		if d.owner != "" {
			methods = append(methods, d)
		}
	}
	return onlyDefinition(methods)
}

func goImports(root *ast.File) (map[string]string, []string) {
	imports := map[string]string{}
	var paths []string
	if root == nil {
		return imports, paths
	}
	for _, imp := range root.Imports {
		p, err := strconv.Unquote(imp.Path.Value)
		if err != nil {
			continue
		}
		name := path.Base(p)
		if imp.Name != nil {
			name = imp.Name.Name
		}
		imports[name] = p
		paths = append(paths, p)
	}
	return imports, paths
}
