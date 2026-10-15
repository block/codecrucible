package auditctx

import (
	"fmt"
	"strings"
	"testing"
)

func TestMatchDef(t *testing.T) {
	for _, tc := range []struct {
		line string
		name string
		typ  bool
	}{
		{"func (a *App) PageSearch(w http.ResponseWriter, r *http.Request) {", "PageSearch", false},
		{"func Search[T any](q string) {", "Search", false},
		{"type User struct {", "User", true},
		{"export async function performRedirect () {", "performRedirect", false},
		{"export const isRedirectAllowed = (url: string) => {", "isRedirectAllowed", false},
		{"const sanitize = async function (x) {", "sanitize", false},
		{"exports.hashPassword = function (pw) {", "hashPassword", false},
		{"module.exports = function serveMetrics () {", "serveMetrics", false},
		{"    def load_user(self, user_id):", "load_user", false},
		{"class UserSerializer(serializers.ModelSerializer):", "UserSerializer", true},
		{"  suspend fun findAccount(id: Long): Account {", "findAccount", false},
		{"    public ResponseEntity<User> getUser(@PathVariable Long id) {", "getUser", false},
		{"export interface Basket {", "Basket", true},
		{"export type Role = 'admin' | 'user'", "Role", true},
		{"pub(crate) async fn handle_upload(req: Request) -> Response {", "handle_upload", false},
		{"  validate(input) {", "validate", false},
		{"object PaymentLimits {", "PaymentLimits", true},
		{"enum class Direction {", "Direction", true},
		{"internal data class Party(", "Party", true},
		{"@JvmInline value class Token(val raw: String)", "Token", true},
	} {
		d, ok := matchDef(tc.line)
		if !ok || d.Name != tc.name || d.Type != tc.typ {
			t.Errorf("matchDef(%q) = %+v, %v; want %s type=%v", tc.line, d, ok, tc.name, tc.typ)
		}
	}
	for _, line := range []string{"  if (user) {", "  for (const x of xs) {", "\treturn search(q)", "  } catch (err) {"} {
		if d, ok := matchDef(line); ok {
			t.Errorf("matchDef(%q) = %+v; want no definition", line, d)
		}
	}
}

func goRepo() map[string]string {
	return map[string]string{
		"internal/handlers/pages.go": `package handlers

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
		"main.go:1-10 reference to PageSearch",
		"web/templates/search.html:1-2 template search.html",
		"internal/db/queries.go:3-7 definition of SearchDocuments",
		"internal/models/models.go:3-7 type User",
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
	files["b.go"] = "package b\n\nfunc Sink2() {}\n"
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
	if out != want || kept != 3 {
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
		"app/src/main/kotlin/pay/TransferService.kt:1-8 reference to buildTransfer",
		"app/src/test/kotlin/pay/RequestTransferActionTest.kt:1-8 reference to buildTransfer",
		// The constructor receiving the amount, then where it passes it.
		"app/src/main/kotlin/pay/Transfer.kt:3-15 receives the flagged value: Transfer",
		"app/src/main/kotlin/pay/PaymentLimits.kt:6-12 Transfer passes amount to requireValid",
		// Money.of is a library call: the unrelated crypto.of is not retrieved.
		"app/src/main/kotlin/pay/AccountClient.kt:4-6 definition of lookUp",
		"app/src/main/kotlin/pay/Direction.kt:3-7 type Direction",
	}
	if strings.Join(have, "\n") != strings.Join(want, "\n") {
		t.Fatalf("Retrieve =\n%s\nwant\n%s", strings.Join(have, "\n"), strings.Join(want, "\n"))
	}
}

func TestContainingCallsAndParameters(t *testing.T) {
	lines := strings.Split(`fun build(req: Req) =
  outer(
    Transfer(
      req.id,
      Money.of(req.code, req.amount),
    ),
  )`, "\n")
	got := containingCalls(lines, 5, 1)
	if len(got) != 2 || got[0] != (call{name: "Transfer", arg: 1}) || got[1].name != "outer" || got[1].arg != -1 {
		t.Fatalf("containingCalls = %+v", got)
	}
	got = containingCalls([]string{"x = Library.make(", "  amount = v,"}, 2, 1)
	if len(got) != 1 || got[0] != (call{qualifier: "Library", name: "make", arg: 0, param: "amount"}) {
		t.Fatalf("named argument call = %+v", got)
	}
	params, after := parameters([]string{"class Transfer(", "  private val id: String,", "  amount: Money = Money.ZERO,", ") {", "}"}, 0, 5)
	if strings.Join(params, ",") != "id,amount" || after != 4 {
		t.Fatalf("parameters = %v, %d", params, after)
	}
	if params, _ := parameters([]string{"public Transfer(String id, Money amount) {"}, 0, 1); strings.Join(params, ",") != "id,amount" {
		t.Fatalf("Java parameters = %v", params)
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
