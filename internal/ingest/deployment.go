package ingest

import (
	"path"
	"regexp"
	"strings"
)

// deploymentNames are build and deployment files that decide what ships and
// how it is configured. Some sit in directories the analysis filter excludes.
var deploymentNames = regexp.MustCompile(`^(dockerfile(\..+)?|.+\.dockerfile|containerfile|(docker-)?compose(\..+)?\.ya?ml|procfile|app\.ya?ml|app\.json|fly\.toml|render\.ya?ml|vercel\.json|netlify\.toml|serverless\.ya?ml|skaffold\.ya?ml|chart\.ya?ml|values(\..+)?\.ya?ml|kustomization\.ya?ml|\.env(\..+)?|.+\.env|application(-.+)?\.(properties|ya?ml)|bootstrap(-.+)?\.(properties|ya?ml)|appsettings(\..+)?\.json|launchsettings\.json|web\.xml|.+\.tfvars|.+\.tf|makefile|gnumakefile|cmakelists\.txt|.+\.cmake|meson\.build|configure\.ac|build\.gradle(\.kts)?|pom\.xml|jenkinsfile|\.gitlab-ci\.ya?ml|\.goreleaser\.ya?ml|cloudbuild\.ya?ml|buildspec\.ya?ml|wrangler\.toml|package\.json|settings\.py|config\.(js|ts|py|rb|go|json|ya?ml|toml))$`)

var deploymentDirs = []string{".github/workflows/", ".circleci/", ".buildkite/", "k8s/", "kubernetes/", "kube/", "deploy/", "deployment/", "deployments/", "helm/", "charts/", "manifests/", "infra/", "infrastructure/", "ops/", "config/", "conf/", "environments/", "overlays/", "base/"}

var deploymentExts = map[string]bool{".yml": true, ".yaml": true, ".json": true, ".toml": true, ".ini": true, ".properties": true, ".conf": true, ".cfg": true, ".env": true, ".tf": true, ".tfvars": true, ".xml": true, ".sh": true}

// DeploymentFiles selects build and deployment configuration from the
// unfiltered walk. It is evidence for the audit's deployment trace, never
// a scan target: findings are not reported against these files.
func DeploymentFiles(files []SourceFile, maxSize int) map[string]string {
	out := map[string]string{}
	for _, f := range files {
		if maxSize > 0 && len(f.Content) > maxSize || isInVendorDir(f.Path) || inToolDir(f.Path) {
			continue
		}
		if IsDeploymentFile(f.Path) {
			out[f.Path] = f.Content
		}
	}
	return out
}

// Flag definitions and toggling scripts, such as features.yml or a
// ldfeatures script; source code that mentions flags is not configuration.
var flagNames = regexp.MustCompile(`(feature|flag|toggle)`)

var codeExts = map[string]bool{".go": true, ".java": true, ".kt": true, ".js": true, ".ts": true, ".jsx": true, ".tsx": true, ".py": true, ".rb": true, ".cs": true, ".php": true, ".rs": true, ".c": true, ".h": true, ".cpp": true, ".swift": true, ".scala": true, ".md": true, ".html": true}

func IsDeploymentFile(p string) bool {
	lower := strings.ToLower(p)
	if deploymentNames.MatchString(path.Base(lower)) {
		return true
	}
	if flagNames.MatchString(path.Base(lower)) && !codeExts[path.Ext(lower)] {
		return true
	}
	if !deploymentExts[path.Ext(lower)] {
		return false
	}
	if strings.Contains(lower, "/web-inf/") || strings.HasPrefix(lower, "web-inf/") {
		return true
	}
	for _, dir := range deploymentDirs {
		if strings.HasPrefix(lower, dir) || strings.Contains(lower, "/"+dir) {
			return true
		}
	}
	return false
}

// Editor and agent tooling state is never deployed.
var toolDirs = []string{".beads/", ".perles/", ".claude/", ".cursor/", ".idea/", ".vscode/", ".devcontainer/", ".git/"}

func inToolDir(p string) bool {
	lower := strings.ToLower(p)
	for _, dir := range toolDirs {
		if strings.HasPrefix(lower, dir) || strings.Contains(lower, "/"+dir) {
			return true
		}
	}
	return false
}
