package sourceindex

import "testing"

func TestMatchDef(t *testing.T) {
	for _, tc := range []struct {
		line string
		name string
		typ  bool
	}{
		{"export async function performRedirect () {", "performRedirect", false},
		{"export const isRedirectAllowed = (url: string) => {", "isRedirectAllowed", false},
		{"const sanitize = async function (x) {", "sanitize", false},
		{"exports.hashPassword = function (pw) {", "hashPassword", false},
		{"module.exports = function serveMetrics () {", "serveMetrics", false},
		{"    def load_user(self, user_id):", "load_user", false},
		{"class UserSerializer(serializers.ModelSerializer):", "UserSerializer", true},
		{"    public ResponseEntity<User> getUser(@PathVariable Long id) {", "getUser", false},
		{"export interface Basket {", "Basket", true},
		{"export type Role = 'admin' | 'user'", "Role", true},
		{"pub(crate) async fn handle_upload(req: Request) -> Response {", "handle_upload", false},
		{"  validate(input) {", "validate", false},
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
