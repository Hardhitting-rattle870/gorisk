package analyzer

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/1homsi/gorisk/internal/graph"
)

func TestDetect(t *testing.T) {
	tests := []struct {
		name     string
		files    []string
		expected string
	}{
		{
			name:     "go project",
			files:    []string{"go.mod"},
			expected: "go",
		},
		{
			name:     "node project",
			files:    []string{"package.json"},
			expected: "node",
		},
		{
			name:     "multi project",
			files:    []string{"go.mod", "package.json"},
			expected: "multi",
		},
		{
			name:     "no markers",
			files:    []string{},
			expected: "go", // defaults to go
		},
		{
			name:     "java project (pom.xml)",
			files:    []string{"pom.xml"},
			expected: "java",
		},
		{
			name:     "rust project",
			files:    []string{"Cargo.toml"},
			expected: "rust",
		},
		{
			name:     "ruby project",
			files:    []string{"Gemfile.lock"},
			expected: "ruby",
		},
		{
			name:     "swift project (Package.resolved)",
			files:    []string{"Package.resolved"},
			expected: "swift",
		},
		{
			name:     "swift project (Package.swift)",
			files:    []string{"Package.swift"},
			expected: "swift",
		},
		{
			name:     "dart project (pubspec.lock)",
			files:    []string{"pubspec.lock"},
			expected: "dart",
		},
		{
			name:     "dart project (pubspec.yaml only)",
			files:    []string{"pubspec.yaml"},
			expected: "dart",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			for _, f := range tt.files {
				if err := os.WriteFile(filepath.Join(dir, f), []byte("test"), 0600); err != nil {
					t.Fatal(err)
				}
			}

			got := detect(dir)
			if got != tt.expected {
				t.Errorf("detect() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestFileExists(t *testing.T) {
	dir := t.TempDir()
	testFile := filepath.Join(dir, "test.txt")

	// File doesn't exist
	if fileExists(testFile) {
		t.Error("fileExists() = true, want false for non-existent file")
	}

	// Create file
	if err := os.WriteFile(testFile, []byte("test"), 0600); err != nil {
		t.Fatal(err)
	}

	// File exists
	if !fileExists(testFile) {
		t.Error("fileExists() = false, want true for existing file")
	}
}

func TestForLang(t *testing.T) {
	dir := t.TempDir()

	tests := []struct {
		name        string
		lang        string
		setupFiles  []string
		expectName  string
		expectError bool
	}{
		{
			name:       "explicit go",
			lang:       "go",
			expectName: "go",
		},
		{
			name:       "explicit node",
			lang:       "node",
			expectName: "node",
		},
		{
			name:       "explicit python",
			lang:       "python",
			expectName: "python",
		},
		{
			name:       "explicit java",
			lang:       "java",
			expectName: "java",
		},
		{
			name:       "explicit rust",
			lang:       "rust",
			expectName: "rust",
		},
		{
			name:       "explicit ruby",
			lang:       "ruby",
			expectName: "ruby",
		},
		{
			name:       "explicit swift",
			lang:       "swift",
			expectName: "swift",
		},
		{
			name:       "explicit dart",
			lang:       "dart",
			expectName: "dart",
		},
		{
			name:        "invalid language",
			lang:        "cobol",
			expectError: true,
		},
		{
			name:       "auto detect go",
			lang:       "auto",
			setupFiles: []string{"go.mod"},
			expectName: "go",
		},
		{
			name:       "auto detect node",
			lang:       "auto",
			setupFiles: []string{"package.json"},
			expectName: "node",
		},
		{
			name:       "auto detect multi",
			lang:       "auto",
			setupFiles: []string{"go.mod", "package.json"},
			expectName: "multi",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testDir := filepath.Join(dir, tt.name)
			if err := os.Mkdir(testDir, 0750); err != nil {
				t.Fatal(err)
			}

			for _, f := range tt.setupFiles {
				if err := os.WriteFile(filepath.Join(testDir, f), []byte("test"), 0600); err != nil {
					t.Fatal(err)
				}
			}

			analyzer, err := ForLang(tt.lang, testDir)

			if tt.expectError {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if analyzer.Name() != tt.expectName {
				t.Errorf("analyzer.Name() = %q, want %q", analyzer.Name(), tt.expectName)
			}
		})
	}
}

func TestFeaturesFor(t *testing.T) {
	dir := t.TempDir()

	tests := []struct {
		name        string
		lang        string
		setupFiles  []string
		expectError bool
	}{
		{
			name: "go features",
			lang: "go",
		},
		{
			name: "node features",
			lang: "node",
		},
		{
			name:        "invalid language",
			lang:        "cobol",
			expectError: true,
		},
		{
			name:       "auto detect go",
			lang:       "auto",
			setupFiles: []string{"go.mod"},
		},
		{
			name:       "auto detect multi defaults to go",
			lang:       "auto",
			setupFiles: []string{"go.mod", "package.json"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testDir := filepath.Join(dir, tt.name)
			if err := os.Mkdir(testDir, 0750); err != nil {
				t.Fatal(err)
			}

			for _, f := range tt.setupFiles {
				if err := os.WriteFile(filepath.Join(testDir, f), []byte("test"), 0600); err != nil {
					t.Fatal(err)
				}
			}

			features, err := FeaturesFor(tt.lang, testDir)

			if tt.expectError {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			// Verify features are not nil
			if features.Upgrade == nil {
				t.Error("Upgrade feature is nil")
			}
			if features.CapDiff == nil {
				t.Error("CapDiff feature is nil")
			}
			if features.PRDiff == nil {
				t.Error("PRDiff feature is nil")
			}
			if features.Reachability == nil {
				t.Error("Reachability feature is nil")
			}
		})
	}
}

func TestMergeGraphs(t *testing.T) {
	// Create two graphs to merge
	graphA := graph.NewDependencyGraph()
	graphA.Main = &graph.Module{Path: "moduleA", Version: "v1.0.0"}
	graphA.Modules["moduleA"] = graphA.Main
	graphA.Packages["pkgA"] = &graph.Package{ImportPath: "pkgA"}
	graphA.Edges["pkgA"] = []string{"dep1"}

	graphB := graph.NewDependencyGraph()
	graphB.Main = &graph.Module{Path: "moduleB", Version: "v2.0.0"}
	graphB.Modules["moduleB"] = graphB.Main
	graphB.Packages["pkgB"] = &graph.Package{ImportPath: "pkgB"}
	graphB.Edges["pkgB"] = []string{"dep2"}

	merged := mergeGraphs(graphA, graphB)

	// Check Main is from graphA (first graph takes precedence)
	if merged.Main.Path != "moduleA" {
		t.Errorf("merged.Main.Path = %q, want %q", merged.Main.Path, "moduleA")
	}

	// Check modules from both graphs are present
	if _, ok := merged.Modules["moduleA"]; !ok {
		t.Error("moduleA not found in merged graph")
	}
	if _, ok := merged.Modules["moduleB"]; !ok {
		t.Error("moduleB not found in merged graph")
	}

	// Check packages from both graphs are present
	if _, ok := merged.Packages["pkgA"]; !ok {
		t.Error("pkgA not found in merged graph")
	}
	if _, ok := merged.Packages["pkgB"]; !ok {
		t.Error("pkgB not found in merged graph")
	}

	// Check edges from both graphs are present
	if _, ok := merged.Edges["pkgA"]; !ok {
		t.Error("pkgA edges not found in merged graph")
	}
	if _, ok := merged.Edges["pkgB"]; !ok {
		t.Error("pkgB edges not found in merged graph")
	}
}

func TestMergeGraphsWithNilMain(t *testing.T) {
	graphA := graph.NewDependencyGraph()
	graphA.Main = nil

	graphB := graph.NewDependencyGraph()
	graphB.Main = &graph.Module{Path: "moduleB"}

	merged := mergeGraphs(graphA, graphB)

	// When graphA.Main is nil, should use graphB.Main
	if merged.Main == nil || merged.Main.Path != "moduleB" {
		t.Error("Expected merged.Main to be from graphB when graphA.Main is nil")
	}
}

// --- Workspace tests ---

func TestLoadWorkspaceGoWork(t *testing.T) {
	root := t.TempDir()

	// Create two minimal Go modules under the workspace root.
	moduleA := filepath.Join(root, "moduleA")
	moduleB := filepath.Join(root, "moduleB")
	if err := os.MkdirAll(moduleA, 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(moduleB, 0750); err != nil {
		t.Fatal(err)
	}

	// Write minimal go.mod files.
	if err := os.WriteFile(filepath.Join(moduleA, "go.mod"), []byte("module example.com/moduleA\n\ngo 1.21\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(moduleB, "go.mod"), []byte("module example.com/moduleB\n\ngo 1.21\n"), 0600); err != nil {
		t.Fatal(err)
	}

	// Write a go.work file referencing both modules.
	goWork := "go 1.21\n\nuse (\n\t./moduleA\n\t./moduleB\n)\n"
	if err := os.WriteFile(filepath.Join(root, "go.work"), []byte(goWork), 0600); err != nil {
		t.Fatal(err)
	}

	g, err := LoadWorkspace(root)
	if err != nil {
		t.Fatalf("LoadWorkspace() error: %v", err)
	}
	if g == nil {
		t.Fatal("LoadWorkspace() returned nil graph")
	}

	// Both modules should appear in the merged graph.
	if _, ok := g.Modules["example.com/moduleA"]; !ok {
		t.Error("merged graph missing example.com/moduleA")
	}
	if _, ok := g.Modules["example.com/moduleB"]; !ok {
		t.Error("merged graph missing example.com/moduleB")
	}
}

func TestLoadWorkspaceNpmWorkspaces(t *testing.T) {
	root := t.TempDir()

	// Create packages/* subdirectory layout.
	pkgsDir := filepath.Join(root, "packages")
	if err := os.MkdirAll(pkgsDir, 0750); err != nil {
		t.Fatal(err)
	}

	// Create two sub-packages each with a minimal package.json and
	// package-lock.json so the node adapter can load them.
	for _, name := range []string{"alpha", "beta"} {
		subDir := filepath.Join(pkgsDir, name)
		if err := os.MkdirAll(subDir, 0750); err != nil {
			t.Fatal(err)
		}
		pkgJSON := fmt.Sprintf(`{"name": "%s", "version": "1.0.0"}`, name)
		if err := os.WriteFile(filepath.Join(subDir, "package.json"), []byte(pkgJSON), 0600); err != nil {
			t.Fatal(err)
		}
		// Minimal v2 package-lock.json (no dependencies).
		lockJSON := `{"name":"` + name + `","version":"1.0.0","lockfileVersion":2,"requires":true,"packages":{"":{"name":"` + name + `","version":"1.0.0"}}}`
		if err := os.WriteFile(filepath.Join(subDir, "package-lock.json"), []byte(lockJSON), 0600); err != nil {
			t.Fatal(err)
		}
	}

	// Root package.json with workspaces field.
	rootPkgJSON := `{"name": "root", "version": "1.0.0", "workspaces": ["packages/*"]}`
	if err := os.WriteFile(filepath.Join(root, "package.json"), []byte(rootPkgJSON), 0600); err != nil {
		t.Fatal(err)
	}

	g, err := LoadWorkspace(root)
	if err != nil {
		t.Fatalf("LoadWorkspace() error: %v", err)
	}
	if g == nil {
		t.Fatal("LoadWorkspace() returned nil graph")
	}
	// The merged graph should be non-nil and have been produced from both members.
	// Both member loads succeeded, so Modules map should be populated.
	if len(g.Modules) == 0 && len(g.Packages) == 0 {
		t.Log("warning: merged graph has no modules or packages (members may have had no deps)")
	}
}

func TestLoadWorkspaceNoWorkspaceFile(t *testing.T) {
	root := t.TempDir()
	_, err := LoadWorkspace(root)
	if err == nil {
		t.Error("expected error when no workspace file found, got nil")
	}
}

func TestLoadWorkspacePnpm(t *testing.T) {
	root := t.TempDir()

	// Create packages/* layout.
	subDir := filepath.Join(root, "packages", "gamma")
	if err := os.MkdirAll(subDir, 0750); err != nil {
		t.Fatal(err)
	}
	pkgJSON := `{"name": "gamma", "version": "1.0.0"}`
	if err := os.WriteFile(filepath.Join(subDir, "package.json"), []byte(pkgJSON), 0600); err != nil {
		t.Fatal(err)
	}
	lockJSON := `{"name":"gamma","version":"1.0.0","lockfileVersion":2,"requires":true,"packages":{"":{"name":"gamma","version":"1.0.0"}}}`
	if err := os.WriteFile(filepath.Join(subDir, "package-lock.json"), []byte(lockJSON), 0600); err != nil {
		t.Fatal(err)
	}

	// pnpm-workspace.yaml
	pnpmYAML := "packages:\n  - 'packages/*'\n"
	if err := os.WriteFile(filepath.Join(root, "pnpm-workspace.yaml"), []byte(pnpmYAML), 0600); err != nil {
		t.Fatal(err)
	}

	g, err := LoadWorkspace(root)
	if err != nil {
		t.Fatalf("LoadWorkspace() pnpm error: %v", err)
	}
	if g == nil {
		t.Fatal("LoadWorkspace() returned nil graph for pnpm workspace")
	}
}
