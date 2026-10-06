package ingest

import (
	"strings"
	"testing"
)

func TestIsDeploymentFile(t *testing.T) {
	for path, want := range map[string]bool{
		"Dockerfile":                          true,
		"build/api.Dockerfile":                true,
		"docker-compose.prod.yml":             true,
		".env.production":                     true,
		".github/workflows/deploy.yml":        true,
		"deploy/k8s/deployment.yaml":          true,
		"charts/api/values.yaml":              true,
		"src/main/resources/application.yml":  true,
		"WebContent/WEB-INF/web.xml":          true,
		"WebContent/WEB-INF/spring-beans.xml": true,
		"config/features.yml":                 true,
		"scripts/toggle_flags.sh":             true,
		"Makefile":                            true,
		"package.json":                        true,
		"src/flags.go":                        false,
		"src/FeatureFlags.java":               false,
		"internal/handler.go":                 false,
		"docs/deploy.md":                      false,
		"testdata/sample.yaml":                false,
	} {
		if got := IsDeploymentFile(path); got != want {
			t.Errorf("IsDeploymentFile(%q) = %v, want %v", path, got, want)
		}
	}
}

func TestDeploymentFilesSkipsVendorToolingAndOversized(t *testing.T) {
	files := []SourceFile{
		{Path: "Dockerfile", Content: "FROM scratch\n"},
		{Path: "vendor/x/Dockerfile", Content: "FROM scratch\n"},
		{Path: ".beads/config.yaml", Content: "sync: false\n"},
		{Path: "config/big.yaml", Content: strings.Repeat("x: 1\n", 10)},
		{Path: "main.go", Content: "package main\n"},
	}
	got := DeploymentFiles(files, 20)
	if len(got) != 1 || got["Dockerfile"] == "" {
		t.Fatalf("DeploymentFiles = %v", got)
	}
}
