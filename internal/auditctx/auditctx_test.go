package auditctx

import (
	"fmt"
	"strings"
	"testing"
)

func goRepo() map[string]string {
	return map[string]string{
		"internal/handlers/pages.go": `package handlers; import "example/internal/models"

var searchTmpl *texttmpl.Template

func Load(dir string) {
	searchTmpl, _ = texttmpl.ParseFiles(filepath.Join(dir, "search.html"))
}

func (a *App) PageSearch(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	docs := a.DB.SearchDocuments(q)
	var u models.User
	_ = searchTmpl.Execute(w, map[string]any{"Query": q, "Results": docs, "User": u})
}
`,
		"main.go": `package main

func routes(a *handlers.App) {
	r := chi.NewRouter()
	r.Group(func(r chi.Router) {
		r.Use(auth.RequireAuth)
		r.Get("/search", a.PageSearch)
	})
}
`,
		"internal/db/queries.go": `package db

func (d *DB) SearchDocuments(q string) []Document {
	rows := d.Query("SELECT * FROM docs WHERE title LIKE '%" + q + "%'")
	return scan(rows)
}

func scan(rows *Rows) []Document { return nil }
`,
		"internal/models/models.go": `package models

type User struct {
	ID   int64
	Role string ` + "`json:\"role\"`" + `
}
`,
		"web/templates/search.html": "<h1>Results for {{.Query}}</h1>\n",
	}
}

func TestRetrieveFindsCallersTemplatesAndDefinitions(t *testing.T) {
	ix := NewIndex(goRepo())
	got := ix.Retrieve(Claim{File: "internal/handlers/pages.go", Start: 13, End: 13}, map[string]bool{"internal/handlers/pages.go": true})
	want := []string{
		"main.go:1-9 reference to PageSearch",
		"web/templates/search.html:1-1 template search.html",
		"internal/db/queries.go:3-6 definition of SearchDocuments",
		"internal/models/models.go:3-6 type User",
	}
	var have []string
	for _, e := range got {
		have = append(have, fmt.Sprintf("%s:%d-%d %s", e.File, e.Start, e.End, e.Reason))
	}
	if strings.Join(have, "\n") != strings.Join(want, "\n") {
		t.Fatalf("Retrieve =\n%s\nwant\n%s", strings.Join(have, "\n"), strings.Join(want, "\n"))
	}

	skipped := ix.Retrieve(Claim{File: "internal/handlers/pages.go", Start: 13, End: 13}, map[string]bool{"main.go": true, "web/templates/search.html": true})
	for _, e := range skipped {
		if e.File == "main.go" || e.File == "web/templates/search.html" {
			t.Errorf("retrieved a file already sent: %+v", e)
		}
	}
}

func TestRetrieveSkipsCommonNames(t *testing.T) {
	files := map[string]string{"a.go": "package a\n\nfunc handler() {\n\tsink()\n}\n"}
	for i := 0; i < maxCallerSpan+1; i++ {
		files[fmt.Sprintf("u%d.go", i)] = "package u\n\nvar _ = handler\nvar _ = Sink2\n"
	}
	files["a.go"] = "package a\n\nfunc handler() {\n\tSink2()\n}\n"
	files["b.go"] = "package a\n\nfunc Sink2() {}\n"
	ix := NewIndex(files)
	for _, e := range ix.Retrieve(Claim{File: "a.go", Start: 4}, nil) {
		if strings.HasPrefix(e.Reason, "reference to") {
			t.Errorf("generic caller retrieved: %+v", e)
		}
	}
	// Sink2 is referenced from too many files to retrieve its callers, but
	// its single definition is still retrieved as a callee.
	files["a.go"] = "package a\n\nfunc Caller() {\n\tSink2()\n}\n"
	ix = NewIndex(files)
	got := ix.Retrieve(Claim{File: "a.go", Start: 4}, nil)
	if len(got) != 1 || got[0].Reason != "definition of Sink2" {
		t.Errorf("Retrieve = %+v", got)
	}
}

func TestRenderMergesRangesWithinBudget(t *testing.T) {
	ix := NewIndex(map[string]string{"a.go": "l1\nl2\nl3\nl4\nl5\nl6\nl7\nl8\nl9\n", "b.go": strings.Repeat("x\n", 50)})
	count := func(s string) int { return len(s) }
	out, kept := Render(ix, []Excerpt{
		{File: "a.go", Start: 2, End: 3},
		{File: "a.go", Start: 3, End: 4},
		{File: "a.go", Start: 7, End: 8},
		{File: "a.go", Start: 2, End: 2}, // already covered
		{File: "b.go", Start: 1, End: 50},
	}, 60, count)
	want := "<file path=\"a.go\" lines=\"2-4,7-8\">\n2| l2\n3| l3\n4| l4\n...\n7| l7\n8| l8\n</file>\n\n"
	// Three admitted excerpts plus the contained excerpt are all covered.
	if out != want || kept != 4 {
		t.Fatalf("Render = %q (kept %d); want %q", out, kept, want)
	}
}

// kotlinRepo models a handler whose client-supplied amount is validated two
// calls away: the Transfer constructor passes it to PaymentLimits.requireValid.
func kotlinRepo() map[string]string {
	return map[string]string{
		"app/src/main/kotlin/pay/RequestTransferAction.kt": `package pay

class RequestTransferAction(private val accounts: AccountClient) {
  fun handle(req: TransferRequest): TransferResponse {
    val transfer = buildTransfer(req)
    return TransferResponse(transfer.id)
  }

  private fun buildTransfer(req: TransferRequest): Transfer =
    Transfer(
      id = req.idempotencyKey,
      direction = Direction.OUTBOUND,
      account = accounts.lookUp(req.accountToken),
      amount = Money.of(req.currencyCode, req.amount),
      memo = req.memo,
    )
}
`,
		"app/src/main/kotlin/pay/Transfer.kt": `package pay

class Transfer(
  id: String,
  direction: Direction,
  account: Account,
  amount: Money,
  memo: String?,
) {
  val id: String = id
  private val direction: Direction = direction
  private val amount: Money = PaymentLimits.requireValid(amount)
  private val memo: String? = memo?.let { Memo.truncate(it) }
}
`,
		"app/src/main/kotlin/pay/PaymentLimits.kt": `package pay

object PaymentLimits {
  const val MAX_CENTS = 99_999_999L

  fun requireValid(amount: Money): Money {
    require(amount.currency() == Currency.USD) { "USD only" }
    require(amount.cents() in 1..MAX_CENTS) { "out of range" }
    return amount
  }
}
`,
		"app/src/main/kotlin/pay/Direction.kt":                 "package pay\n\nenum class Direction {\n  INBOUND,\n  OUTBOUND,\n}\n",
		"app/src/main/kotlin/pay/Memo.kt":                      "package pay\n\nobject Memo {\n  fun truncate(s: String): String = s.take(140)\n}\n",
		"app/src/main/kotlin/pay/AccountClient.kt":             "package pay\n\nclass AccountClient {\n  fun lookUp(token: String): Account = Account(token)\n}\n",
		"app/src/main/kotlin/crypto/Context.kt":                "package crypto\n\nfun of(vararg parts: String): Context = Context(parts.toList())\n",
		"app/src/test/kotlin/pay/RequestTransferActionTest.kt": "package pay\n\nclass RequestTransferActionTest {\n  fun builds() {\n    action.buildTransfer(request)\n  }\n}\n",
		"app/src/main/kotlin/pay/TransferService.kt":           "package pay\n\nclass TransferService {\n  fun submit(req: TransferRequest) {\n    val t = action.buildTransfer(req)\n  }\n}\n",
	}
}

func TestRetrieveFollowsFlaggedValueIntoConstructor(t *testing.T) {
	ix := NewIndex(kotlinRepo())
	claim := "app/src/main/kotlin/pay/RequestTransferAction.kt"
	var have []string
	for _, e := range ix.Retrieve(Claim{File: claim, Start: 14, End: 14}, map[string]bool{claim: true}) {
		have = append(have, fmt.Sprintf("%s:%d-%d %s", e.File, e.Start, e.End, e.Reason))
	}
	want := []string{
		// A caller outside tests comes before one in a test.
		"app/src/main/kotlin/pay/TransferService.kt:1-7 reference to buildTransfer",
		"app/src/test/kotlin/pay/RequestTransferActionTest.kt:1-7 reference to buildTransfer",
		// The constructor receiving the amount, then where it passes it.
		"app/src/main/kotlin/pay/Transfer.kt:3-14 receives the flagged expression: Transfer",
		"app/src/main/kotlin/pay/PaymentLimits.kt:6-10 possible use of Transfer parameter amount in requireValid",
		// Money.of is a library call: the unrelated crypto.of is not retrieved.
		"app/src/main/kotlin/pay/AccountClient.kt:4-4 definition of lookUp",
		"app/src/main/kotlin/pay/Direction.kt:3-6 type Direction",
	}
	if strings.Join(have, "\n") != strings.Join(want, "\n") {
		t.Fatalf("Retrieve =\n%s\nwant\n%s", strings.Join(have, "\n"), strings.Join(want, "\n"))
	}
}

func TestTestPath(t *testing.T) {
	for path, want := range map[string]bool{
		"app/src/test/kotlin/pay/ActionTest.kt": true,
		"pkg/handler_test.go":                   true,
		"web/src/login.spec.ts":                 true,
		"tests/test_views.py":                   true,
		"app/src/main/kotlin/pay/Action.kt":     false,
		"internal/attestation/verify.go":        false,
	} {
		if got := testPath(path); got != want {
			t.Errorf("testPath(%q) = %v, want %v", path, got, want)
		}
	}
}
