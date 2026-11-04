package sourceindex

import (
	"reflect"
	"testing"
)

func TestJavaScriptImportBasenames(t *testing.T) {
	for _, tc := range []struct {
		name, specifier, status string
		files                   []string
		want                    []string
	}{
		{"dotted basename", "./config.types", "resolved", []string{"config.types.ts"}, []string{"config.types.ts"}},
		{"exact dotted file", "./config.types", "resolved", []string{"config.types", "config.types.ts"}, []string{"config.types"}},
		{"exact extensionless file", "./config", "resolved", []string{"config", "config.ts"}, []string{"config"}},
		{"explicit source extension", "./config.ts", "resolved", []string{"config.ts", "config.ts.ts"}, []string{"config.ts"}},
		{"missing explicit extension", "./config.ts", "unresolved", []string{"config.ts.ts"}, nil},
		{"ambiguous dotted basename", "./config.types", "ambiguous", []string{"config.types.js", "config.types.ts"}, nil},
		{"dotted directory", "./config.types", "resolved", []string{"config.types/index.ts"}, []string{"config.types/index.ts"}},
		{"missing local file", "./config.types", "unresolved", nil, nil},
		{"external package", "config.types", "skipped", []string{"config.types.ts"}, nil},
		{"vendored import", "./node_modules/config.types", "skipped", []string{"node_modules/config.types.ts"}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			files := map[string]string{"app.ts": "import '" + tc.specifier + "'"}
			for _, file := range tc.files {
				files[file] = "export const value = 1"
			}
			ix := New(files)
			if got := ix.ImportGraph()["app.ts"]; !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("resolved targets = %v, want %v", got, tc.want)
			}
			if imports := ix.Imports(); len(imports) != 1 || imports[0].Status != tc.status {
				t.Fatalf("import = %+v, want status %q", imports, tc.status)
			}
		})
	}
}
