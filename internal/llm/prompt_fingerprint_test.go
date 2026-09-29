package llm

import (
	"testing"
	"testing/fstest"
)

func TestPromptFingerprintSnapshotsUsedBytes(t *testing.T) {
	fsys := fstest.MapFS{"security_analysis_base.yaml": &fstest.MapFile{Data: []byte("system_message: Original\n")}}
	loader := NewPromptLoader(fsys)
	before, err := loader.Fingerprint()
	if err != nil {
		t.Fatal(err)
	}
	fsys["security_analysis_base.yaml"] = &fstest.MapFile{Data: []byte("system_message: Changed\n")}
	base, err := loader.LoadBasePrompt()
	if err != nil {
		t.Fatal(err)
	}
	if base.SystemMessage != "Original" {
		t.Fatal("fingerprint and prompt bytes diverged")
	}
	after, err := loader.Fingerprint()
	if err != nil {
		t.Fatal(err)
	}
	if after != before {
		t.Fatal("snapshot changed")
	}
	newDigest, err := NewPromptLoader(fsys).Fingerprint()
	if err != nil {
		t.Fatal(err)
	}
	if newDigest == before {
		t.Fatal("template edit did not change fingerprint")
	}
	fsys["unrelated.txt"] = &fstest.MapFile{Data: []byte("not a prompt")}
	unrelated, err := NewPromptLoader(fsys).Fingerprint()
	if err != nil {
		t.Fatal(err)
	}
	if unrelated != newDigest {
		t.Fatal("unrelated file changed prompt identity")
	}
}
