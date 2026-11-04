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
