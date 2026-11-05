package auditctx

import (
	"strings"
	"testing"
)

func retrievedText(files map[string]string, file string, line int) string {
	ix := NewIndex(files)
	out, _ := Render(ix, ix.Retrieve(Claim{File: file, Start: line, End: line}, map[string]bool{file: true}), 100000, func(s string) int { return len(s) })
	return out
}

func TestRetrieveLocalNamespaceImport(t *testing.T) {
	files := map[string]string{
		"entry.ts":      "import * as Validation from './validation';\nexport function submit(value: string) {\n  return Validation.validateInput(value);\n}\n",
		"validation.ts": "export function validateInput(value: string) {\n  if (!allowed(value)) throw new Error('invalid');\n  return value;\n}\n",
	}
	if got := retrievedText(files, "entry.ts", 3); !strings.Contains(got, "throw new Error") {
		t.Fatalf("local namespace validator missing: %s", got)
	}
}

func TestRetrieveGoParameterForwarding(t *testing.T) {
	files := map[string]string{
		"entry.go":    "package pay\nfunc submit(input Money) {\n accept(\n  input,\n )\n}\n",
		"accept.go":   "package pay\nfunc accept(amount Money) {\n validateAmount(amount)\n}\n",
		"validate.go": "package pay\nfunc validateAmount(amount Money) {\n if amount.Cents <= 0 { panic(\"invalid amount\") }\n}\n",
	}
	if got := retrievedText(files, "entry.go", 4); !strings.Contains(got, "invalid amount") {
		t.Fatalf("Go parameter forwarding lost the guard: %s", got)
	}
}

func TestRetrieveSameFileForwardedGuard(t *testing.T) {
	files := kotlinRepo()
	p := "app/src/main/kotlin/pay/Transfer.kt"
	files[p] = strings.ReplaceAll(files[p], "PaymentLimits.requireValid(amount)", "requireValid(amount)") +
		"\nfun requireValid(amount: Money): Money {\n require(amount.cents() > 0)\n return amount\n}\n"
	delete(files, "app/src/main/kotlin/pay/PaymentLimits.kt")
	claim := "app/src/main/kotlin/pay/RequestTransferAction.kt"
	if got := retrievedText(files, claim, 14); !strings.Contains(got, "require(amount.cents() > 0)") {
		t.Fatalf("guard beyond the constructor excerpt was lost: %s", got)
	}
}

func TestRetrieveCallerIncludesMountedMiddleware(t *testing.T) {
	files := map[string]string{
		"handlers.ts": "export function listRecords() {\n return (req, res) => res.json(load(req.body.owner));\n}\n",
		"router.ts":   "import { listRecords } from './handlers';\nimport { bindOwner } from './identity';\n" + strings.Repeat("// routing configuration\n", 20) + "router.get('/records', bindOwner(), listRecords());\n",
		"identity.ts": "export function bindOwner() {\n return (req, res, next) => {\n  req.body.owner = req.auth.id;\n  next();\n };\n}\n",
	}
	got := retrievedText(files, "handlers.ts", 2)
	for _, want := range []string{"router.get('/records'", "req.body.owner = req.auth.id"} {
		if !strings.Contains(got, want) {
			t.Fatalf("caller context missing %q: %s", want, got)
		}
	}
}

func TestRetrieveGoCallerIncludesWrapper(t *testing.T) {
	files := map[string]string{
		"handler.go":  "package app\nfunc readRecords(w Writer, r Request) {\n write(w, load(r.Owner))\n}\n",
		"router.go":   "package app\nfunc routes(m Mux) {\n m.Handle(\"/records\", bindOwner(readRecords))\n}\n",
		"identity.go": "package app\nfunc bindOwner(next Handler) Handler {\n return func(w Writer, r Request) { r.Owner = r.Principal; next(w, r) }\n}\n",
	}
	if got := retrievedText(files, "handler.go", 3); !strings.Contains(got, "r.Owner = r.Principal") {
		t.Fatalf("Go caller wrapper missing: %s", got)
	}
}

func TestRetrieveCallerIncludesBareMiddlewareReference(t *testing.T) {
	files := map[string]string{
		"handlers.ts": "export function listRecords(req, res) {\n return res.json(load(req.body.owner));\n}\n",
		"router.ts":   "import { listRecords } from './handlers';\nimport { bindOwner } from './identity';\nrouter.get('/records', bindOwner, listRecords);\n",
		"identity.ts": "export function bindOwner(req, res, next) {\n req.body.owner = req.auth.id;\n next();\n}\n",
	}
	if got := retrievedText(files, "handlers.ts", 2); !strings.Contains(got, "req.body.owner = req.auth.id") {
		t.Fatalf("bare middleware reference missing: %s", got)
	}
}
