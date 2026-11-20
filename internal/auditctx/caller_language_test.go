package auditctx

import (
	"strings"
	"testing"
)

// Caller-definition retrieval holds no language rules of its own: statement
// boundaries, names and import bindings come from the source index. These
// cases pin the same behavior outside JavaScript.

func TestPythonCallerIncludesImportedWrapperAndIgnoresComments(t *testing.T) {
	files := map[string]string{
		"app/handlers.py": "def list_records(request):\n    return load(request.owner)\n",
		"app/urls.py": "from .guards import require_owner\nfrom .handlers import list_records\n" +
			"# urlpatterns = [path('old', commented_guard(list_records))]\n" +
			"urlpatterns = [\n    path('records', require_owner(list_records)),\n]\n",
		"app/guards.py": "def require_owner(view):\n    OWNER_GUARD = view\n    return OWNER_GUARD\n",
		"app/old.py":    "def commented_guard(view):\n    return 'COMMENTED_GUARD'\n",
	}
	got := retrievedText(files, "app/handlers.py", 2)
	if !strings.Contains(got, "OWNER_GUARD = view") || strings.Contains(got, "COMMENTED_GUARD") {
		t.Fatalf("python caller context wrong: %s", got)
	}
}

func TestPythonExternalImportDoesNotResolveLocalNamesake(t *testing.T) {
	files := map[string]string{
		"app/handlers.py": "def list_records(request):\n    return load(request.owner)\n",
		"app/urls.py":     "from flask_login import login_required\nfrom .handlers import list_records\nroute('/records', login_required(list_records))\n",
		"app/local.py":    "def login_required(view):\n    return 'LOCAL_NAMESAKE'\n",
	}
	got := retrievedText(files, "app/handlers.py", 2)
	if strings.Contains(got, "LOCAL_NAMESAKE") || !strings.Contains(got, "unresolved or external caller reference login_required") {
		t.Fatal(got)
	}
}

func TestPythonImportResolvesAmbiguousName(t *testing.T) {
	// Two modules declare the guard; the import says which one is meant.
	files := map[string]string{
		"app/handlers.py": "def list_records(request):\n    return load(request.owner)\n",
		"app/urls.py":     "from .guards import require_owner\nfrom .handlers import list_records\nroute('/records', require_owner(list_records))\n",
		"app/guards.py":   "def require_owner(view):\n    return 'IMPORTED_GUARD'\n",
		"app/other.py":    "def require_owner(view):\n    return 'OTHER_GUARD'\n",
	}
	got := retrievedText(files, "app/handlers.py", 2)
	if !strings.Contains(got, "IMPORTED_GUARD") || strings.Contains(got, "OTHER_GUARD") || strings.Contains(got, "ambiguous") {
		t.Fatal(got)
	}
}

func TestKotlinCallerIncludesWrapper(t *testing.T) {
	files := map[string]string{
		"src/pay/Handlers.kt":      "package pay\n\nfun listRecords(call: Call) {\n    respond(call, load(call.owner))\n}\n",
		"src/pay/Routes.kt":        "package pay\n\nimport pay.guards.requireOwner\n\nfun routes(r: Router) {\n    r.get(\"/records\", requireOwner(listRecords))\n}\n",
		"src/pay/guards/Guards.kt": "package pay.guards\n\nfun requireOwner(next: Handler): Handler {\n    val OWNER_GUARD = next\n    return OWNER_GUARD\n}\n",
	}
	got := retrievedText(files, "src/pay/Handlers.kt", 4)
	if !strings.Contains(got, "val OWNER_GUARD = next") || strings.Contains(got, "caller reference get") {
		t.Fatalf("kotlin caller wrapper missing: %s", got)
	}
}
