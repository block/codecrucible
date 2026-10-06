package ingest

import (
	"reflect"
	"sort"
	"testing"
)

func TestOptionalDependencyGraphLanguages(t *testing.T) {
	for _, tc := range []struct {
		name  string
		files []SourceFile
		from  string
		want  []string
	}{
		{"js multi-line import and aliases", []SourceFile{
			{Path: "src/app.ts", Content: "import {\n  auth,\n} from './auth.js'\nimport db from '@/db'\nconst u = require('../lib/util.cjs')\nimport 'lodash'\n"},
			{Path: "src/auth.ts", Content: ""}, {Path: "src/db/index.ts", Content: ""}, {Path: "lib/util.cjs", Content: ""},
		}, "src/app.ts", []string{"lib/util.cjs", "src/auth.ts", "src/db/index.ts"}},
		{"python submodules and src layout", []SourceFile{
			{Path: "src/pkg/views.py", Content: "from pkg.auth import (\n    check,\n    roles,\n)\nfrom . import models\nimport pkg.db, os\n"},
			{Path: "src/pkg/auth/__init__.py", Content: ""}, {Path: "src/pkg/auth/roles.py", Content: ""},
			{Path: "src/pkg/models.py", Content: ""}, {Path: "src/pkg/db.py", Content: ""},
		}, "src/pkg/views.py", []string{"src/pkg/auth/__init__.py", "src/pkg/auth/roles.py", "src/pkg/db.py", "src/pkg/models.py"}},
		{"jvm packages and imports", []SourceFile{
			{Path: "app/src/Web.java", Content: "package com.x.web;\nimport com.x.auth.Guard;\nimport static com.x.util.Strings.clean;\nimport com.x.db.*;\nimport java.util.List;\n"},
			{Path: "app/src/Routes.java", Content: "package com.x.web;\n"},
			{Path: "auth/Guard.kt", Content: "package com.x.auth\n"}, {Path: "auth/Other.kt", Content: "package com.x.auth\n"},
			{Path: "util/Strings.java", Content: "package com.x.util;\n"},
			{Path: "db/A.java", Content: "package com.x.db;\n"}, {Path: "db/B.java", Content: "package com.x.db;\n"},
		}, "app/src/Web.java", []string{"app/src/Routes.java", "auth/Guard.kt", "db/A.java", "db/B.java", "util/Strings.java"}},
		{"kotlin top-level function import", []SourceFile{
			{Path: "a/Main.kt", Content: "package app\nimport app.util.sanitize\n"},
			{Path: "u/Text.kt", Content: "package app.util\nfun sanitize() {}\n"},
		}, "a/Main.kt", []string{"u/Text.kt"}},
		{"csharp namespaces", []SourceFile{
			{Path: "Web/Ctl.cs", Content: "using System;\nusing App.Auth;\nusing static App.Util.Paths;\nnamespace App.Web;\n"},
			{Path: "Web/Other.cs", Content: "namespace App.Web\n{\n}\n"},
			{Path: "Auth/Policy.cs", Content: "namespace App.Auth;\n"},
			{Path: "Util/Paths.cs", Content: "namespace App.Util;\n"}, {Path: "Util/Other.cs", Content: "namespace App.Util;\n"},
		}, "Web/Ctl.cs", []string{"Auth/Policy.cs", "Util/Paths.cs", "Web/Other.cs"}},
		{"php namespaces, use groups, require", []SourceFile{
			{Path: "app/Http/Ctl.php", Content: "<?php\nnamespace App\\Http;\nuse App\\Models\\{User, Post};\nuse App\\Auth\\Gate as G;\nrequire_once __DIR__ . '/../helpers.php';\n"},
			{Path: "app/Http/Base.php", Content: "<?php\nnamespace App\\Http;\nabstract class Base {}\n"},
			{Path: "app/Models/User.php", Content: "<?php\nnamespace App\\Models;\nfinal class User {}\n"},
			{Path: "app/Models/Post.php", Content: "<?php\nnamespace App\\Models;\nclass Post {}\n"},
			{Path: "app/Models/Other.php", Content: "<?php\nnamespace App\\Models;\nclass Other {}\n"},
			{Path: "lib/Gate.php", Content: "<?php\nnamespace App\\Auth;\nclass Gate {}\n"},
			{Path: "app/helpers.php", Content: "<?php\n"},
		}, "app/Http/Ctl.php", []string{"app/Http/Base.php", "app/Models/Post.php", "app/Models/User.php", "app/helpers.php", "lib/Gate.php"}},
		{"rust modules and use paths", []SourceFile{
			{Path: "src/lib.rs", Content: "mod api;\npub mod db;\n"},
			{Path: "src/api.rs", Content: "mod auth;\nuse crate::db::{pool::Pool, Conn};\nuse super::lib_only;\nuse self::auth::check;\n"},
			{Path: "src/api/auth.rs", Content: ""}, {Path: "src/db/mod.rs", Content: ""}, {Path: "src/db/pool.rs", Content: ""},
		}, "src/api.rs", []string{"src/api/auth.rs", "src/db/mod.rs", "src/db/pool.rs"}},
		{"c includes and pairs", []SourceFile{
			{Path: "src/net/conn.c", Content: "#include <stdio.h>\n#include \"conn.h\"\n#include \"util/buf.h\"\n#include <proj/log.h>\n"},
			{Path: "src/net/conn.h", Content: ""}, {Path: "src/util/buf.h", Content: ""}, {Path: "include/proj/log.h", Content: ""},
		}, "src/net/conn.c", []string{"include/proj/log.h", "src/net/conn.h", "src/util/buf.h"}},
		{"swift module directory", []SourceFile{
			{Path: "Sources/App/A.swift", Content: ""}, {Path: "Sources/App/B.swift", Content: ""}, {Path: "Sources/Other/C.swift", Content: ""},
		}, "Sources/App/A.swift", []string{"Sources/App/B.swift"}},
		{"ruby require_relative", []SourceFile{
			{Path: "app/a.rb", Content: "require_relative 'lib/b'\n"}, {Path: "app/lib/b.rb", Content: ""},
		}, "app/a.rb", []string{"app/lib/b.rb"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := append([]string{}, ResolveDependencies(tc.files)[tc.from]...)
			sort.Strings(got)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("edges = %v, want %v", got, tc.want)
			}
		})
	}
}
