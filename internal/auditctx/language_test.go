package auditctx

import (
	"strings"
	"testing"
)

func lineOf(text, needle string) int {
	i := strings.Index(text, needle)
	if i < 0 {
		panic("missing test marker: " + needle)
	}
	return strings.Count(text[:i], "\n") + 1
}

func TestGoReceiverGroupedAndGenericParameters(t *testing.T) {
	files := map[string]string{
		"entry.go":    "package pay\nfunc submit(v Validator, a, b Money) {\n v.Accept(\n a,\n b,\n )\n}\n",
		"accept.go":   "package pay\nfunc (v *Validator) Accept(first, amount Money) {\n validateAmount[Money](amount)\n}\n",
		"validate.go": "package pay\nfunc validateAmount[T Money](amount T) {\n enforcePositive(amount)\n}\n",
	}
	if got := retrievedText(files, "entry.go", 5); !strings.Contains(got, "enforcePositive") {
		t.Fatalf("receiver or grouped parameters confused the argument binding: %s", got)
	}
}

func TestGoImportAliasAndExternalPackage(t *testing.T) {
	files := map[string]string{
		"entry.go":            "package app\nimport V \"example.com/app/checks\"\nfunc submit(amount int) {\n V.Accept(amount)\n}\n",
		"checks/accept.go":    "package checks\nfunc Accept(amount int) {\n validateAmount(amount)\n}\n",
		"checks/validate.go":  "package checks\nfunc validateAmount(amount int) {\n if amount <= 0 { panic(\"invalid\") }\n}\n",
		"unrelated/accept.go": "package unrelated\nfunc Accept(amount int) { panic(\"wrong package\") }\n",
	}
	if got := retrievedText(files, "entry.go", 4); !strings.Contains(got, "invalid") || strings.Contains(got, "wrong package") {
		t.Fatalf("import alias resolution failed: %s", got)
	}
	files["entry.go"] = strings.ReplaceAll(files["entry.go"], "example.com/app/checks", "external.example/library")
	if got := retrievedText(files, "entry.go", 4); strings.Contains(got, "func Accept") {
		t.Fatalf("external import resolved to a local namesake: %s", got)
	}
}

func TestKotlinImportAliases(t *testing.T) {
	for _, methodAlias := range []bool{false, true} {
		t.Run(map[bool]string{false: "object alias", true: "function alias"}[methodAlias], func(t *testing.T) {
			files := kotlinRepo()
			claim := "app/src/main/kotlin/pay/RequestTransferAction.kt"
			files[claim] = strings.ReplaceAll(files[claim], "package pay", "package pay\nimport pay.Transfer as Payment")
			files[claim] = strings.ReplaceAll(files[claim], "    Transfer(", "    Payment(")
			p := "app/src/main/kotlin/pay/Transfer.kt"
			imp, ref := "pay.PaymentLimits as Checks", "Checks.requireValid"
			if methodAlias {
				imp, ref = "pay.PaymentLimits.requireValid as ensureValid", "ensureValid"
			}
			files[p] = strings.ReplaceAll(files[p], "PaymentLimits.requireValid", ref)
			files[p] = strings.ReplaceAll(files[p], "package pay", "package pay\nimport "+imp)
			if got := retrievedText(files, claim, lineOf(files[claim], "amount = Money.of")); !strings.Contains(got, "amount.cents() in 1..MAX_CENTS") {
				t.Fatalf("aliased constructor/guard missing: %s", got)
			}
		})
	}
}

func TestKotlinDeclarationForms(t *testing.T) {
	for _, declaration := range []string{
		"object Guard {\n fun check(amount: Money) = validateAmount(amount)\n}",
		"enum class Guard { INBOUND, OUTBOUND }",
		"internal data class Guard(val amount: Money)",
		"@JvmInline value class Guard(val amount: Money)",
	} {
		files := map[string]string{"entry.kt": "fun submit(value: Guard) {}\n", "guard.kt": declaration + "\n"}
		got := retrievedText(files, "entry.kt", 1)
		for _, line := range strings.Split(declaration, "\n") {
			if !strings.Contains(got, line) {
				t.Fatalf("Kotlin declaration not retrieved: %s\n%s", declaration, got)
			}
		}
	}
}

func TestNestedCallResultsAreNotBoundAsTheFlaggedArgument(t *testing.T) {
	files := map[string]string{
		"entry.kt":   "fun submit(input: Money) =\n outer(\n  accept(\n   input,\n  ),\n )\n",
		"accept.kt":  "fun accept(amount: Money): Receipt {\n validateAmount(amount)\n return Receipt()\n}\n",
		"outer.kt":   "fun outer(receipt: Receipt) {\n validateReceipt(receipt)\n}\n",
		"amount.kt":  "fun validateAmount(amount: Money) = require(amount.cents() > 0)\n",
		"receipt.kt": "fun validateReceipt(receipt: Receipt) = require(receipt.id != null)\n",
	}
	got := retrievedText(files, "entry.kt", 4)
	if !strings.Contains(got, "amount.cents() > 0") || strings.Contains(got, "receipt.id != null") {
		t.Fatalf("outer call's result was confused with the flagged argument: %s", got)
	}
}

func TestKotlinOverloadsRemainUnresolved(t *testing.T) {
	files := kotlinRepo()
	guard := "app/src/main/kotlin/pay/PaymentLimits.kt"
	files[guard] = strings.Replace(files[guard], "  fun requireValid", "  fun requireValid(amount: Long): Long = amount\n  fun requireValid", 1)
	claim := "app/src/main/kotlin/pay/RequestTransferAction.kt"
	if got := retrievedText(files, claim, 14); strings.Contains(got, "MAX_CENTS") {
		t.Fatalf("selected one overload without type evidence: %s", got)
	}
}

func TestKotlinCallSyntaxDoesNotInventForwarding(t *testing.T) {
	files := map[string]string{
		"entry.kt": "package pay\nfun submit(input: Money) =\n accept(\n  memo = \"), validateWrong(input)\",\n  amount = input,\n )\n",
		"accept.kt": `package pay
fun accept(memo: String, amount: Money) {
  // validateWrong(amount)
  /* outer /* validateWrong(amount) */ still a comment */
  val text = "validateWrong(amount)"
  val raw = """validateWrong(amount), )"""
  record(validateAmount(amount)); validateWrong(memo)
}
`,
		"good.kt":  "package pay\nfun validateAmount(amount: Money) {\n require(amount.cents() > 0)\n}\n",
		"wrong.kt": "package pay\nfun validateWrong(memo: String) {\n error(\"decoy guard\")\n}\n",
	}
	if got := retrievedText(files, "entry.kt", 5); !strings.Contains(got, "require(amount.cents() > 0)") || strings.Contains(got, "decoy guard") {
		t.Fatalf("comments, strings or adjacent calls affected binding: %s", got)
	}
}

func TestAmbiguousInlineArgumentsDoNotBind(t *testing.T) {
	files := map[string]string{
		"entry.kt":  "package pay\nfun submit(input: Money) {\n accept(other, input)\n}\n",
		"accept.kt": "package pay\nfun accept(first: Money, amount: Money) {\n validateAmount(amount)\n}\n",
		"guard.kt":  "package pay\nfun validateAmount(amount: Money) {\n require(amount.cents() > 0)\n}\n",
	}
	if got := retrievedText(files, "entry.kt", 3); !strings.Contains(got, "fun accept") || strings.Contains(got, "require(amount.cents() > 0)") {
		t.Fatalf("line-only location must not pick between two arguments: %s", got)
	}
}

func TestSameFileGuardBeyondExcerptLimit(t *testing.T) {
	files := map[string]string{
		"entry.kt":  "package pay\nfun submit(input: Money) {\n accept(input)\n}\n",
		"accept.kt": "package pay\nfun accept(amount: Money) {\n validateAmount(amount)\n" + strings.Repeat(" // padding\n", maxDefLines) + "}\nfun validateAmount(amount: Money) {\n require(amount.cents() > 0)\n}\n",
	}
	if got := retrievedText(files, "entry.kt", 3); !strings.Contains(got, "require(amount.cents() > 0)") || !strings.Contains(got, "...\n") {
		t.Fatalf("an excerpt was treated as the whole file: %s", got)
	}
}

func TestLexicalFallbackStaysLanguageLocal(t *testing.T) {
	for _, ext := range []string{"py", "rs", "java"} {
		t.Run(ext, func(t *testing.T) {
			declaration := map[string]string{"py": "def validateAmount(amount):", "rs": "fn validateAmount(amount: Money) {", "java": "public Money validateAmount(Money amount) {"}[ext]
			file := "guard." + ext
			files := map[string]string{"entry." + ext: "validateAmount(amount)\n", file: declaration + "\n  check_positive(amount)\n", "other.kt": "fun validateAmount(amount: Money) = error(\"decoy\")\n"}
			if got := retrievedText(files, "entry."+ext, 1); !strings.Contains(got, "check_positive") || strings.Contains(got, "decoy") {
				t.Fatalf("fallback lost a unique definition or crossed languages: %s", got)
			}
		})
	}
}

func TestRetrieveInvalidLocations(t *testing.T) {
	ix := NewIndex(map[string]string{"a.kt": "fun submit(x: Int) = x\n", "a.html": "{{x}}"})
	for _, c := range []Claim{{File: "missing", Start: 1}, {File: "a.kt", Start: 0}, {File: "a.kt", Start: 99}, {File: "a.html", Start: 1}} {
		if got := ix.Retrieve(c, nil); len(got) != 0 {
			t.Fatalf("invalid claim retrieved context: %+v", got)
		}
	}
}

func TestTemplateClaimsStillRetrieveIncludes(t *testing.T) {
	files := map[string]string{"page.html": "{% include \"header.html\" %}\n", "header.html": "<h1>{{ title }}</h1>\n"}
	if got := retrievedText(files, "page.html", 1); !strings.Contains(got, "<h1>{{ title }}</h1>") {
		t.Fatalf("template inclusion context was lost: %s", got)
	}
}

func TestMalformedGoRetainsLexicalContextWithoutBinding(t *testing.T) {
	files := map[string]string{
		"entry.go":  "package pay\nfunc submit(input int) {\n accept(input)\n}\n",
		"accept.go": "package pay\nfunc accept(amount int) {\n validateAmount(amount)\n", // missing closing brace
		"guard.go":  "package pay\nfunc validateAmount(amount int) { panic(\"guard\") }\n",
	}
	got := retrievedText(files, "entry.go", 3)
	if !strings.Contains(got, "func accept") || strings.Contains(got, "panic") {
		t.Fatalf("parse failure must retain lexical context without inventing binding: %s", got)
	}
}

func TestNestedScopesDoNotForwardShadowedParameters(t *testing.T) {
	for _, ext := range []string{"go", "kt"} {
		t.Run(ext, func(t *testing.T) {
			files := map[string]string{
				"entry.go":  "package pay\nfunc submit(input int) {\n accept(input)\n}\n",
				"accept.go": "package pay\nfunc accept(amount int) {\n f := func(amount int) { validateAmount(amount) }; f(0)\n}\n",
				"guard.go":  "package pay\nfunc validateAmount(amount int) { panic(\"decoy\") }\n",
				"entry.kt":  "package pay\nfun submit(input: Int) {\n accept(input)\n}\n",
				"accept.kt": "package pay\nfun accept(amount: Int) {\n listOf(0).forEach { amount -> validateAmount(amount) }\n}\n",
				"guard.kt":  "package pay\nfun validateAmount(amount: Int) = error(\"decoy\")\n",
			}
			got := retrievedText(files, "entry."+ext, 3)
			if !strings.Contains(got, "accept") || strings.Contains(got, "decoy") {
				t.Fatalf("nested scope's parameter was confused with receiver's: %s", got)
			}
		})
	}
}

func TestLexicalFallbackKeepsInlineBodiesAndRustLifetimes(t *testing.T) {
	files := map[string]string{
		"entry.ts": "export function submit(value: string) { return Validation.validateInput(value); }\n",
		"guard.ts": "export function validateInput(value: string) { throw new Error('invalid'); }\n",
		"entry.rs": "fn submit<'a>(value: &'a str) {\n validateInput(value);\n}\n",
		"guard.rs": "fn validateInput(value: &str) { panic!(\"invalid\"); }\n",
	}
	for ext, line := range map[string]int{"ts": 1, "rs": 2} {
		if got := retrievedText(files, "entry."+ext, line); !strings.Contains(got, "invalid") {
			t.Fatalf("lexical %s fallback lost context: %s", ext, got)
		}
	}
}

func FuzzRetrieveLocations(f *testing.F) {
	for _, code := range []string{"fun submit(amount: Money) = accept(amount)", "func submit(amount Money) { accept(amount) }", "class A(\n value: Money,\n) { val note = \"), {\" }", "fun broken(amount: Money) { /* unclosed"} {
		f.Add(code, 1)
	}
	f.Fuzz(func(t *testing.T, code string, line int) {
		files := map[string]string{"a.kt": code, "a.go": code, "a.ts": code}
		ix := NewIndex(files)
		for file := range files {
			for _, e := range ix.Retrieve(Claim{File: file, Start: line, End: line}, nil) {
				if e.Start < 1 || e.End < e.Start || e.End > len(ix.source.Lines(e.File)) {
					t.Fatalf("invalid excerpt: %+v", e)
				}
			}
		}
	})
}
