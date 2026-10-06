package decision

import (
	"strings"
	"testing"
)

func selectedText(t *testing.T, files map[string]string, graph map[string][]string, path string, line int) string {
	t.Helper()
	got := NewEvidenceIndex(files, graph).Select([]SourceRange{{Path: path, Start: line}}, 20000)
	if !got.Complete() {
		t.Fatalf("incomplete selection: %+v", got.Gaps)
	}
	text := ""
	for _, e := range got.Evidence {
		text += e.Text + "\n"
	}
	return text
}

func lineOf(t *testing.T, content, needle string) int {
	t.Helper()
	for i, line := range strings.Split(content, "\n") {
		if strings.Contains(line, needle) {
			return i + 1
		}
	}
	t.Fatalf("missing %q", needle)
	return 0
}

func assertText(t *testing.T, text string, want, reject []string) {
	t.Helper()
	for _, w := range want {
		if !strings.Contains(text, w) {
			t.Errorf("missing %q in:\n%s", w, text)
		}
	}
	for _, r := range reject {
		if strings.Contains(text, r) {
			t.Errorf("included unrelated %q in:\n%s", r, text)
		}
	}
}

var unrelated = strings.Repeat("    noise();\n", 5)

func TestStructuralSelectionScopesNonGoLanguages(t *testing.T) {
	for _, tc := range []struct {
		name, path, content, cite string
		want, reject              []string
	}{
		{
			name: "javascript express", path: "app.js", cite: "db.query(",
			content: "const express = require('express')\nconst app = express()\napp.use(authenticate)\n\n" +
				"function authenticate(req, res, next) {\n  if (!req.user) return res.sendStatus(401)\n  next()\n}\n\n" +
				"function unrelated() {\n" + unrelated + "}\n\n" +
				"// Lists users.\napp.get('/users', requireAdmin, async (req, res) => {\n  const q = `SELECT * FROM u WHERE id = ${req.query.id}`\n  res.json(await db.query(q))\n})\n\n" +
				"function requireAdmin(req, res, next) {\n  if (req.user.admin) return next()\n  res.sendStatus(403)\n}\n\n" +
				"app.get('/other', (req, res) => {\n" + unrelated + "})\n",
			want:   []string{"// Lists users.", "app.use(authenticate)", "function authenticate", "if (!req.user)", "function requireAdmin", "const app = express()"},
			reject: []string{"function unrelated", "'/other'"},
		},
		{
			name: "typescript class method", path: "svc.ts", cite: "exec(",
			content: "import { exec } from 'child_process'\n\nexport class Runner extends Base {\n  private readonly shell = '/bin/sh'\n\n" +
				"  @Authorized('admin')\n  async run(cmd: string): Promise<void> {\n    if (!allowed(cmd)) {\n      throw new Error('no')\n    }\n    exec(`${this.shell} -c ${cmd}`)\n  }\n\n" +
				"  other(): void {\n" + unrelated + "  }\n}\n",
			want:   []string{"import { exec }", "export class Runner extends Base", "private readonly shell", "@Authorized('admin')", "if (!allowed(cmd))"},
			reject: []string{"other(): void"},
		},
		{
			name: "python flask", path: "views.py", cite: "os.system",
			content: "import os\nfrom flask import Flask, request\n\napp = Flask(__name__)\nDEBUG = os.environ.get('DEBUG') == '1'\n\n\n" +
				"@app.before_request\ndef check_token():\n    if not request.headers.get('X-Token'):\n        abort(401)\n\n\n" +
				"def unrelated():\n" + unrelated + "\n\n" +
				"# Runs a command.\n@app.route('/run', methods=['POST'])\n@login_required\ndef run():\n    cmd = request.form['cmd']\n    if DEBUG:\n        return f\"{cmd!r} {request.args.get('x', '{')}\"\n    os.system(cmd)\n",
			want:   []string{"# Runs a command.", "@app.route('/run'", "@login_required", "@app.before_request", "def check_token", "DEBUG = os.environ", "import os"},
			reject: []string{"def unrelated"},
		},
		{
			name: "python class member", path: "repo.py", cite: "cursor.execute",
			content: "class Repo(Base):\n    \"\"\"Users.\"\"\"\n    table = 'users'\n\n    def find(self, name):\n        sql = f\"SELECT * FROM {self.table} WHERE n = '{name}'\"\n        return self.cursor.execute(sql)\n\n    def other(self):\n" + strings.Repeat("        noise()\n", 5),
			want:    []string{"class Repo(Base):", "table = 'users'", "def find"},
			reject:  []string{"def other"},
		},
		{
			name: "java spring", path: "UserController.java", cite: "repo.query",
			content: "package app;\n\nimport java.util.List;\n\n/** Users. */\n@RestController\n@RequestMapping(\"/api\")\npublic class UserController {\n    private final UserRepo repo;\n    private static final String Q = \"\"\"\n        SELECT * FROM u WHERE n = '%s'\n        \"\"\";\n\n" +
				"    @GetMapping(\"/users/{id}\")\n    @PreAuthorize(\"hasRole('ADMIN')\")\n    public User get(@PathVariable String id) {\n        return repo.query(String.format(Q, id));\n    }\n\n" +
				"    public void other() {\n" + unrelated + "    }\n}\n",
			want:   []string{"@RequestMapping(\"/api\")", "public class UserController", "private final UserRepo repo;", "SELECT * FROM u", "@PreAuthorize", "package app;"},
			reject: []string{"other()"},
		},
		{
			name: "kotlin", path: "Service.kt", cite: "repo.query",
			content: "package app\n\nclass Service(private val repo: Repo) {\n    val table = \"users\"\n\n    suspend fun find(id: String): User? {\n        if (id.isBlank()) return null\n        return repo.query(\"SELECT * FROM ${table} WHERE id = ${id}\")\n    }\n\n    fun other() {\n" + unrelated + "    }\n}\n",
			want:    []string{"class Service(private val repo: Repo)", "val table", "if (id.isBlank())"},
			reject:  []string{"fun other"},
		},
		{
			name: "csharp", path: "FilesController.cs", cite: "PhysicalFile(",
			content: "using Microsoft.AspNetCore.Mvc;\n\nnamespace App\n{\n    [ApiController]\n    [Authorize]\n    public class FilesController : ControllerBase\n    {\n        private readonly string _root = @\"C:\\data\\\";\n\n" +
				"        [HttpGet(\"{name}\")]\n        public IActionResult Get(string name)\n        {\n            var path = $\"{_root}{name}\";\n            return PhysicalFile(path, \"application/octet-stream\");\n        }\n\n" +
				"        public void Other()\n        {\n" + unrelated + "        }\n    }\n}\n",
			want:   []string{"namespace App", "[Authorize]", "public class FilesController", "_root = @", "[HttpGet("},
			reject: []string{"Other()"},
		},
		{
			name: "rust impl", path: "lib.rs", cite: "Command::new",
			content: "use std::process::Command;\n\npub struct Runner {\n    cmd: String,\n}\n\nimpl Runner {\n    /// Runs it.\n    pub fn run(&self) -> Result<(), Error> {\n        if self.cmd.is_empty() {\n            return Err(Error::Empty);\n        }\n        Command::new(&self.cmd).spawn()?;\n        Ok(())\n    }\n\n    fn other<'a>(&'a self) {\n" + unrelated + "    }\n}\n",
			want:    []string{"use std::process::Command;", "impl Runner {", "/// Runs it.", "if self.cmd.is_empty()"},
			reject:  []string{"fn other"},
		},
		{
			name: "php", path: "UserController.php", cite: "DB::select",
			content: "<?php\n\nnamespace App\\Http;\n\nuse Illuminate\\Http\\Request;\n\n#[Middleware('auth')]\nclass UserController extends Controller\n{\n    private $table = 'users';\n\n" +
				"    public function show(Request $request, $id)\n    {\n        $sql = \"SELECT * FROM {$this->table} WHERE id = $id\";\n        return DB::select($sql);\n    }\n\n    public function other()\n    {\n" + unrelated + "    }\n}\n",
			want:   []string{"#[Middleware('auth')]", "class UserController", "private $table", "public function show"},
			reject: []string{"function other"},
		},
		{
			name: "c", path: "conn.c", cite: "strcpy(",
			content: "#include <string.h>\n\nstruct conn {\n    int fd;\n    char buf[256];\n};\n\n" +
				"static int checked(const char *in)\n{\n    return strlen(in) < 256;\n}\n\n" +
				"int handle(struct conn *c, const char *in) {\n    if (!checked(in)) {\n        return -1;\n    }\n#ifdef DEBUG\n    puts(in);\n#endif\n    strcpy(c->buf, in);\n    return 0;\n}\n\n" +
				"void other(void)\n{\n" + unrelated + "}\n",
			want:   []string{"int handle(", "static int checked", "char buf[256];", "#ifdef DEBUG"},
			reject: []string{"void other"},
		},
		{
			name: "swift", path: "Client.swift", cite: "URLSession",
			content: "import Foundation\n\nstruct Client {\n    let base: URL\n\n    func fetch(_ path: String) async throws -> Data {\n        let url = base.appendingPathComponent(\"\\(path)\")\n        guard url.scheme == \"https\" else {\n            throw ClientError.insecure\n        }\n        return try await URLSession.shared.data(from: url).0\n    }\n\n    func other() {\n" + unrelated + "    }\n}\n",
			want:    []string{"struct Client {", "let base: URL", "guard url.scheme"},
			reject:  []string{"func other"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, ok := structuralUnits(tc.path, tc.content); !ok {
				t.Fatal("parse fell back to whole file")
			}
			text := selectedText(t, map[string]string{tc.path: tc.content}, nil, tc.path, lineOf(t, tc.content, tc.cite))
			assertText(t, text, tc.want, tc.reject)
		})
	}
}

func TestStructuralUnitsFallBackWhenStructureIsUncertain(t *testing.T) {
	for _, tc := range []struct{ name, path, content string }{
		{"unbalanced", "a.js", "function f() {\n  if (x) {\n    run()\n}\n"},
		{"unterminated string", "a.ts", "const s = 'oops\nrun()\n"},
		{"unterminated comment", "a.java", "class A {\n /* open\n}\n"},
		{"php template", "a.php", "<?php if ($x): ?>\n<div><?= $y ?></div>\n"},
		{"php without open tag", "a.php", "<html><?php echo 1; ?></html>\n"},
		{"scala 3 braceless", "a.scala", "object Main:\n  def run(): Unit =\n    exec()\nend Main\n"},
		{"python bad dedent", "a.py", "def f():\n        a()\n    b()\n"},
		{"python orphan decorator", "a.py", "@route\nx = 1\n"},
		{"python unterminated", "a.py", "s = '''open\n"},
		{"jsx text", "a.jsx", "function A() {\n  return <p>Don't</p>\n}\n"},
		{"preprocessor braces", "a.c", "#ifdef A\nint f() {\n#else\nint f(int x) {\n#endif\n  return 0;\n}\n"},
		{"unsupported language", "a.rb", "def f\n  run\nend\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if units, ok := structuralUnits(tc.path, tc.content); ok {
				t.Fatalf("accepted uncertain structure: %d units", len(units))
			}
			// The index still supplies the whole file.
			lines := strings.Count(strings.TrimSuffix(tc.content, "\n"), "\n") + 1
			got := NewEvidenceIndex(map[string]string{tc.path: tc.content}, nil).Select([]SourceRange{{Path: tc.path, Start: 1}}, 20000)
			if !got.Complete() || got.Evidence[len(got.Evidence)-1].End != lines {
				t.Fatalf("whole-file fallback missing: %+v", got)
			}
		})
	}
}

func TestStructuralUnitsKeepContinuedStatementsTogether(t *testing.T) {
	for _, tc := range []struct{ name, path, content string }{
		{"js chain", "a.js", "app\n  .use(auth)\n  .get('/x', h)\n"},
		{"js if else", "a.js", "if (a) {\n  x()\n}\nelse {\n  y()\n}\n"},
		{"js try", "a.js", "try {\n  x()\n} catch (e) {\n  y()\n} finally {\n  z()\n}\n"},
		{"js multiline import", "a.ts", "import {\n  a,\n  b,\n} from './x'\n"},
		{"js arrow", "a.js", "const f = () =>\n  run()\n"},
		{"js regex", "a.js", "const re = /[}{]/g\n"},
		{"kotlin expression body", "a.kt", "fun f() =\n    run()\n"},
		{"kotlin annotation", "a.kt", "@Throws(IOException::class)\nfun f() {\n    run()\n}\n"},
		{"java multi-line call", "A.java", "class A {\n    void f() {}\n}\nstatic {\n    init(\n        a);\n}\n"},
		{"python continuation", "a.py", "x = (1 +\n     2)\ny = 3 \\\n    + 4\n"},
		{"python try", "a.py", "try:\n    import ujson as json\nexcept ImportError:\n    import json\n"},
		{"rust raw string", "a.rs", "fn f() {\n    let s = r#\"}\"#;\n}\n"},
		{"cpp raw string", "a.cpp", "void f() {\n    auto s = R\"x(})x\";\n}\n"},
		{"csharp verbatim", "a.cs", "class A {\n    string s = @\"\\\";\n}\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			units, ok := structuralUnits(tc.path, tc.content)
			if !ok {
				t.Fatal("parse fell back")
			}
			top := 0
			for _, u := range units {
				if u.parent == nil {
					top++
				}
			}
			want := 1
			if tc.name == "python continuation" || tc.name == "java multi-line call" {
				want = 2
			}
			if top != want {
				for _, u := range units {
					t.Logf("%d-%d container=%v", u.Start, u.End, u.container)
				}
				t.Fatalf("got %d top-level units, want %d", top, want)
			}
		})
	}
}

func TestStructuralUnitsDescribeDeclarations(t *testing.T) {
	content := "import { a } from './a'\nexport const x = 1, y = 2\nexport default function handler(req) {\n  return a(req)\n}\nexport type T = { n: number }\n"
	units, ok := structuralUnits("a.ts", content)
	if !ok || len(units) != 4 {
		t.Fatalf("units: %v %d", ok, len(units))
	}
	if !units[0].header || !units[1].names["x"] || !units[2].names["handler"] || !units[2].function || !units[3].names["T"] {
		t.Fatalf("misdescribed units: %+v %+v %+v %+v", units[0], units[1], units[2], units[3])
	}
	units, ok = structuralUnits("a.py", "from x import y\n\n@app.before_request\ndef guard():\n    pass\n\nclass A:\n    n: int = 1\n    def m(self):\n        pass\n")
	if !ok || len(units) != 5 || !units[0].header || !units[1].guard || !units[2].container || units[3].parent != units[2] || !units[3].names["n"] || !units[4].names["m"] {
		t.Fatalf("misdescribed python units: %v %d", ok, len(units))
	}
}

func TestStructuralSelectionIncludesImporterGuards(t *testing.T) {
	files := map[string]string{
		"app.js":    "const express = require('express')\nconst users = require('./users')\nconst app = express()\napp.use(session)\napp.use('/users', users)\n\nfunction session(req, res, next) {\n  if (!req.cookies.sid) return res.sendStatus(401)\n  next()\n}\n\nfunction unrelated() {\n" + unrelated + "}\n",
		"users.js":  "const router = require('express').Router()\n\nrouter.get('/:id', (req, res) => {\n  res.send(db.query('SELECT ' + req.params.id))\n})\n\nmodule.exports = router\n",
		"unused.js": "function noise() {\n" + unrelated + "}\n",
	}
	graph := map[string][]string{"app.js": {"users.js"}}
	text := selectedText(t, files, graph, "users.js", 4)
	assertText(t, text, []string{"router.get('/:id'", "app.use(session)", "function session", "if (!req.cookies.sid)", "app.use('/users', users)"}, []string{"function unrelated", "noise"})
}

func TestStructuralSelectionOnlyPrecedingSameScopeGuards(t *testing.T) {
	content := "router.get('/open', open)\nrouter.use(auth)\nrouter.get('/closed', closed)\n\nfunction open(req, res) {\n  res.send(read())\n}\n\nfunction closed(req, res) {\n  res.send(read())\n}\n\nfunction auth(req, res, next) {\n  next()\n}\n"
	files := map[string]string{"r.js": content}
	assertText(t, selectedText(t, files, nil, "r.js", 6), []string{"router.get('/open', open)"}, []string{"router.use(auth)", "function auth"})
	assertText(t, selectedText(t, files, nil, "r.js", 10), []string{"router.get('/closed', closed)", "router.use(auth)", "function auth"}, nil)
}
