package analyzer

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	dartadapter "github.com/1homsi/gorisk/internal/adapters/dart"
	elixiradapter "github.com/1homsi/gorisk/internal/adapters/elixir"
	goadapter "github.com/1homsi/gorisk/internal/adapters/go"
	javaadapter "github.com/1homsi/gorisk/internal/adapters/java"
	nodeadapter "github.com/1homsi/gorisk/internal/adapters/node"
	phpadapter "github.com/1homsi/gorisk/internal/adapters/php"
	pythonadapter "github.com/1homsi/gorisk/internal/adapters/python"
	rubyadapter "github.com/1homsi/gorisk/internal/adapters/ruby"
	rustadapter "github.com/1homsi/gorisk/internal/adapters/rust"
	swiftadapter "github.com/1homsi/gorisk/internal/adapters/swift"
	"github.com/1homsi/gorisk/internal/graph"
	"github.com/1homsi/gorisk/internal/prdiff"
	"github.com/1homsi/gorisk/internal/reachability"
	"github.com/1homsi/gorisk/internal/upgrade"
)

// LangFeatures holds the feature implementations registered for a language.
type LangFeatures struct {
	Upgrade      upgrade.Upgrader
	CapDiff      upgrade.CapDiffer
	PRDiff       prdiff.Differ
	Reachability reachability.Analyzer
}

var registry = map[string]LangFeatures{
	"go": {
		Upgrade:      upgrade.GoUpgrader{},
		CapDiff:      upgrade.GoCapDiffer{},
		PRDiff:       prdiff.GoDiffer{},
		Reachability: reachability.GoAnalyzer{},
	},
	"node": {
		Upgrade:      upgrade.NodeUpgrader{},
		CapDiff:      upgrade.NodeCapDiffer{},
		PRDiff:       prdiff.NodeDiffer{},
		Reachability: reachability.NodeAnalyzer{},
	},
	"php": {
		Upgrade:      upgrade.PHPUpgrader{},
		CapDiff:      upgrade.PHPCapDiffer{},
		PRDiff:       prdiff.PHPDiffer{},
		Reachability: reachability.PHPAnalyzer{},
	},
	"python": {},
	"java":   {},
	"rust":   {},
	"ruby":   {},
	"elixir": {},
	"swift":  {},
	"dart":   {},
}

// FeaturesFor returns the feature implementations for the given language.
// lang may be "auto", "go", "node", "php", "python", "java", "rust", or "ruby".
func FeaturesFor(lang, dir string) (LangFeatures, error) {
	if lang == "auto" || lang == "" {
		lang = detect(dir)
		if lang == "multi" {
			lang = "go" // multi-repo: default to go for non-graph features
		}
	}
	f, ok := registry[lang]
	if !ok {
		return LangFeatures{}, fmt.Errorf("unknown language %q; choose auto|go|node|php|python|java|rust|ruby|elixir|dart|swift", lang)
	}
	return f, nil
}

// Analyzer loads a dependency graph for a project directory.
type Analyzer interface {
	Name() string
	Load(dir string) (*graph.DependencyGraph, error)
}

// ForLang returns an Analyzer for the given language specifier.
// lang may be "auto", "go", "node", "php", "python", "java", "rust", or "ruby".
// "auto" detects from go.mod / package.json / composer.json / requirements.txt /
// pom.xml / Cargo.toml / Gemfile presence.
func ForLang(lang, dir string) (Analyzer, error) {
	if lang == "auto" {
		lang = detect(dir)
	}
	switch lang {
	case "go":
		return &goadapter.Adapter{}, nil
	case "node":
		return &nodeadapter.Adapter{}, nil
	case "php":
		return &phpadapter.Adapter{}, nil
	case "python":
		return &pythonadapter.Adapter{}, nil
	case "java":
		return &javaadapter.Adapter{}, nil
	case "rust":
		return &rustadapter.Adapter{}, nil
	case "ruby":
		return &rubyadapter.Adapter{}, nil
	case "dart":
		return dartadapter.Adapter{}, nil
	case "elixir":
		return elixiradapter.Adapter{}, nil
	case "swift":
		return &swiftadapter.Adapter{}, nil
	case "multi":
		return &multiAnalyzer{}, nil
	default:
		return nil, fmt.Errorf("unknown language %q; choose auto|go|node|php|python|java|rust|ruby|elixir|dart|swift", lang)
	}
}

func detect(dir string) string {
	hasGoMod := fileExists(filepath.Join(dir, "go.mod"))
	hasPkgJSON := fileExists(filepath.Join(dir, "package.json"))
	hasComposerJSON := fileExists(filepath.Join(dir, "composer.json"))
	hasComposerLock := fileExists(filepath.Join(dir, "composer.lock"))
	hasPyprojectTOML := fileExists(filepath.Join(dir, "pyproject.toml"))
	hasPoetryLock := fileExists(filepath.Join(dir, "poetry.lock"))
	hasPipfileLock := fileExists(filepath.Join(dir, "Pipfile.lock"))
	hasRequirementsTxt := fileExists(filepath.Join(dir, "requirements.txt"))
	hasPomXML := fileExists(filepath.Join(dir, "pom.xml"))
	hasGradleLock := fileExists(filepath.Join(dir, "gradle.lockfile"))
	hasBuildGradle := fileExists(filepath.Join(dir, "build.gradle")) || fileExists(filepath.Join(dir, "build.gradle.kts"))
	hasCargoToml := fileExists(filepath.Join(dir, "Cargo.toml"))
	hasGemfileLock := fileExists(filepath.Join(dir, "Gemfile.lock"))
	hasGemfile := fileExists(filepath.Join(dir, "Gemfile"))
	hasPubspecLock := fileExists(filepath.Join(dir, "pubspec.lock"))
	hasPubspecYAML := fileExists(filepath.Join(dir, "pubspec.yaml"))
	hasMixLock := fileExists(filepath.Join(dir, "mix.lock"))
	hasMixExs := fileExists(filepath.Join(dir, "mix.exs"))
	hasPackageResolved := fileExists(filepath.Join(dir, "Package.resolved"))
	hasPackageSwift := fileExists(filepath.Join(dir, "Package.swift"))

	isPython := hasPyprojectTOML || hasPoetryLock || hasPipfileLock || hasRequirementsTxt
	isJava := hasPomXML || hasGradleLock || hasBuildGradle
	isRust := hasCargoToml
	isRuby := hasGemfileLock || hasGemfile
	isDart := hasPubspecLock || hasPubspecYAML
	isElixir := hasMixLock || hasMixExs
	isSwift := hasPackageResolved || hasPackageSwift

	switch {
	case hasGoMod && hasPkgJSON:
		return "multi"
	case hasGoMod:
		return "go"
	case hasPkgJSON:
		return "node"
	case hasComposerJSON || hasComposerLock:
		return "php"
	case isPython:
		return "python"
	case isJava:
		return "java"
	case isRust:
		return "rust"
	case isRuby:
		return "ruby"
	case isDart:
		return "dart"
	case isElixir:
		return "elixir"
	case isSwift:
		return "swift"
	default:
		return "go"
	}
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// ResolveLang resolves "auto" to a concrete language key using project detection.
// It may return "multi".
func ResolveLang(lang, dir string) string {
	if lang == "auto" || lang == "" {
		return detect(dir)
	}
	return lang
}

// multiAnalyzer runs both Go and Node analyzers and merges the results.
type multiAnalyzer struct{}

func (m *multiAnalyzer) Name() string { return "multi" }

func (m *multiAnalyzer) Load(dir string) (*graph.DependencyGraph, error) {
	goA := &goadapter.Adapter{}
	nodeA := &nodeadapter.Adapter{}

	goG, goErr := goA.Load(dir)
	nodeG, nodeErr := nodeA.Load(dir)

	if goErr != nil && nodeErr != nil {
		return nil, fmt.Errorf("go: %w; node: %w", goErr, nodeErr)
	}
	if goErr != nil {
		return nodeG, nil
	}
	if nodeErr != nil {
		return goG, nil
	}
	return mergeGraphs(goG, nodeG), nil
}

func mergeGraphs(a, b *graph.DependencyGraph) *graph.DependencyGraph {
	merged := graph.NewDependencyGraph()
	if a.Main != nil {
		merged.Main = a.Main
	} else {
		merged.Main = b.Main
	}
	for k, v := range a.Modules {
		merged.Modules[k] = v
	}
	for k, v := range b.Modules {
		merged.Modules[k] = v
	}
	for k, v := range a.Packages {
		merged.Packages[k] = v
	}
	for k, v := range b.Packages {
		merged.Packages[k] = v
	}
	for k, v := range a.Edges {
		merged.Edges[k] = v
	}
	for k, v := range b.Edges {
		merged.Edges[k] = v
	}
	return merged
}

// LoadWorkspace detects a monorepo/workspace root and scans all members as a
// unified project. It supports three workspace formats:
//
//   - go.work             → Go workspace (contains multiple Go modules via "use" directives)
//   - package.json with   → npm workspaces (supports glob patterns like "packages/*")
//     "workspaces" field
//   - pnpm-workspace.yaml → pnpm workspace (packages: list)
//
// For each workspace member directory, the appropriate language adapter's
// Load method is called and the resulting graphs are merged.
func LoadWorkspace(root string) (*graph.DependencyGraph, error) {
	// Try go.work first
	if fileExists(filepath.Join(root, "go.work")) {
		return loadGoWorkspace(root)
	}

	// Try pnpm-workspace.yaml
	if fileExists(filepath.Join(root, "pnpm-workspace.yaml")) {
		return loadPnpmWorkspace(root)
	}

	// Try npm workspaces (package.json with "workspaces" field)
	if fileExists(filepath.Join(root, "package.json")) {
		return loadNpmWorkspace(root)
	}

	return nil, fmt.Errorf("no workspace file found in %s (looked for go.work, pnpm-workspace.yaml, package.json with workspaces)", root)
}

// loadGoWorkspace parses go.work and loads each member module.
func loadGoWorkspace(root string) (*graph.DependencyGraph, error) {
	goWorkPath := filepath.Join(root, "go.work")
	f, err := os.Open(goWorkPath)
	if err != nil {
		return nil, fmt.Errorf("open go.work: %w", err)
	}
	defer f.Close()

	var memberDirs []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// Match lines like: use ./path/to/module
		// Also handles the block form: use (\n   ./path\n)
		if strings.HasPrefix(line, "use ") {
			path := strings.TrimSpace(strings.TrimPrefix(line, "use "))
			// Strip parentheses for single-line block form "use ( ./foo )"
			path = strings.Trim(path, "()")
			path = strings.TrimSpace(path)
			if path != "" && path != "(" {
				memberDirs = append(memberDirs, filepath.Join(root, filepath.FromSlash(path)))
			}
		} else if line != "(" && line != ")" && !strings.HasPrefix(line, "//") && !strings.HasPrefix(line, "go ") && !strings.HasPrefix(line, "toolchain ") {
			// Inside a use block, lines are bare paths
			// We handle them if they look like relative paths
			if strings.HasPrefix(line, "./") || strings.HasPrefix(line, "../") {
				memberDirs = append(memberDirs, filepath.Join(root, filepath.FromSlash(line)))
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read go.work: %w", err)
	}

	if len(memberDirs) == 0 {
		return nil, fmt.Errorf("go.work has no 'use' directives")
	}

	goA := &goadapter.Adapter{}
	merged := graph.NewDependencyGraph()
	for _, memberDir := range memberDirs {
		g, err := goA.Load(memberDir)
		if err != nil {
			return nil, fmt.Errorf("load workspace member %s: %w", memberDir, err)
		}
		merged = mergeGraphs(merged, g)
	}
	return merged, nil
}

// loadPnpmWorkspace parses pnpm-workspace.yaml and loads each member.
func loadPnpmWorkspace(root string) (*graph.DependencyGraph, error) {
	data, err := os.ReadFile(filepath.Join(root, "pnpm-workspace.yaml"))
	if err != nil {
		return nil, fmt.Errorf("read pnpm-workspace.yaml: %w", err)
	}

	// Simple YAML parsing: look for lines under "packages:" that start with "  - "
	var patterns []string
	inPackages := false
	for _, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimRight(line, " \t\r")
		if trimmed == "packages:" {
			inPackages = true
			continue
		}
		if inPackages {
			// A new top-level key ends the packages block
			if len(trimmed) > 0 && trimmed[0] != ' ' && trimmed[0] != '\t' && trimmed[0] != '#' && trimmed[0] != '-' {
				inPackages = false
				continue
			}
			// Strip list prefix "  - " or "- "
			item := strings.TrimSpace(trimmed)
			if strings.HasPrefix(item, "- ") {
				item = strings.TrimPrefix(item, "- ")
				item = strings.Trim(item, "\"'")
				patterns = append(patterns, item)
			} else if strings.HasPrefix(item, "-") {
				item = strings.TrimPrefix(item, "-")
				item = strings.TrimSpace(item)
				item = strings.Trim(item, "\"'")
				if item != "" {
					patterns = append(patterns, item)
				}
			}
		}
	}

	memberDirs, err := resolveGlobPatterns(root, patterns)
	if err != nil {
		return nil, fmt.Errorf("resolve pnpm workspace patterns: %w", err)
	}

	return loadNodeMemberDirs(memberDirs)
}

// loadNpmWorkspace parses package.json workspaces field and loads each member.
func loadNpmWorkspace(root string) (*graph.DependencyGraph, error) {
	data, err := os.ReadFile(filepath.Join(root, "package.json"))
	if err != nil {
		return nil, fmt.Errorf("read package.json: %w", err)
	}

	var pkg struct {
		Workspaces []string `json:"workspaces"`
	}
	if err := json.Unmarshal(data, &pkg); err != nil {
		return nil, fmt.Errorf("parse package.json: %w", err)
	}
	if len(pkg.Workspaces) == 0 {
		return nil, fmt.Errorf("package.json has no 'workspaces' field")
	}

	memberDirs, err := resolveGlobPatterns(root, pkg.Workspaces)
	if err != nil {
		return nil, fmt.Errorf("resolve npm workspace patterns: %w", err)
	}

	return loadNodeMemberDirs(memberDirs)
}

// resolveGlobPatterns expands glob patterns relative to root into concrete
// directories that contain a package.json file.
func resolveGlobPatterns(root string, patterns []string) ([]string, error) {
	var dirs []string
	seen := make(map[string]bool)
	for _, pattern := range patterns {
		// Strip trailing "/**" or "/*" — filepath.Glob handles one level; we
		// only need the immediate members.
		globPat := pattern
		if strings.HasSuffix(globPat, "/**") {
			globPat = strings.TrimSuffix(globPat, "/**") + "/*"
		}

		absGlob := filepath.Join(root, filepath.FromSlash(globPat))
		matches, err := filepath.Glob(absGlob)
		if err != nil {
			return nil, fmt.Errorf("glob %q: %w", absGlob, err)
		}

		for _, m := range matches {
			info, err := os.Stat(m)
			if err != nil || !info.IsDir() {
				continue
			}
			if !fileExists(filepath.Join(m, "package.json")) {
				continue
			}
			if !seen[m] {
				seen[m] = true
				dirs = append(dirs, m)
			}
		}
	}
	return dirs, nil
}

// loadNodeMemberDirs loads each member directory with the Node adapter and
// merges the resulting graphs.
func loadNodeMemberDirs(memberDirs []string) (*graph.DependencyGraph, error) {
	if len(memberDirs) == 0 {
		return nil, fmt.Errorf("no workspace members found")
	}

	nodeA := &nodeadapter.Adapter{}
	merged := graph.NewDependencyGraph()
	for _, memberDir := range memberDirs {
		g, err := nodeA.Load(memberDir)
		if err != nil {
			return nil, fmt.Errorf("load workspace member %s: %w", memberDir, err)
		}
		merged = mergeGraphs(merged, g)
	}
	return merged, nil
}
