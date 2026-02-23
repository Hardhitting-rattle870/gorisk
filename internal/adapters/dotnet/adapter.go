// Package dotnet implements a gorisk analyzer for C#/.NET projects.
// It supports packages.lock.json and *.csproj files.
package dotnet

import (
	"os"
	"path/filepath"

	"github.com/1homsi/gorisk/internal/capability"
	"github.com/1homsi/gorisk/internal/graph"
)

// Adapter implements the analyzer.Analyzer interface for C#/.NET projects.
type Adapter struct{}

func (a *Adapter) Name() string { return "dotnet" }

// Load parses the .NET dependency lockfile in dir, detects capabilities from
// .cs source files, and returns a *graph.DependencyGraph.
func (a *Adapter) Load(dir string) (*graph.DependencyGraph, error) {
	pkgs, err := Load(dir)
	if err != nil {
		return nil, err
	}

	g := graph.NewDependencyGraph()

	// Root module — represents the .NET project itself.
	rootName := filepath.Base(dir)

	rootMod := &graph.Module{
		Path: rootName,
		Dir:  dir,
		Main: true,
	}
	g.Modules[rootName] = rootMod
	g.Main = rootMod

	// Root package — detect capabilities from the project's own .cs files.
	rootPkg := &graph.Package{
		ImportPath:   rootName,
		Name:         rootName,
		Module:       rootMod,
		Dir:          dir,
		Capabilities: Detect(dir),
	}
	g.Packages[rootName] = rootPkg
	rootMod.Packages = append(rootMod.Packages, rootPkg)

	var rootEdges []string
	seen := make(map[string]bool)

	for _, dotnetPkg := range pkgs {
		key := dotnetPkg.Name
		if seen[key] {
			continue
		}
		seen[key] = true

		mod := &graph.Module{
			Path:    dotnetPkg.Name,
			Version: dotnetPkg.Version,
		}
		g.Modules[dotnetPkg.Name] = mod

		pkg := &graph.Package{
			ImportPath: dotnetPkg.Name,
			Name:       dotnetPkg.Name,
			Module:     mod,
		}

		// Detect capabilities from installed package source (if available).
		if pkgDir := mod.Dir; pkgDir != "" {
			if _, statErr := os.Stat(pkgDir); statErr == nil {
				pkg.Capabilities = Detect(pkgDir)
			}
		}

		// Apply import-level capabilities for known .NET packages.
		applyDotnetImportCaps(dotnetPkg, pkg)

		g.Packages[dotnetPkg.Name] = pkg
		mod.Packages = append(mod.Packages, pkg)
		g.Edges[dotnetPkg.Name] = dotnetPkg.Dependencies

		if dotnetPkg.Direct {
			rootEdges = append(rootEdges, dotnetPkg.Name)
		}
	}

	g.Edges[rootName] = rootEdges

	return g, nil
}

// applyDotnetImportCaps applies import-level capabilities by matching the
// package name against known .NET patterns using longest-prefix matching.
func applyDotnetImportCaps(dotnetPkg DotnetPackage, pkg *graph.Package) {
	if importCaps := longestPrefixMatch(dotnetPkg.Name); len(importCaps) > 0 {
		for _, c := range importCaps {
			pkg.Capabilities.AddWithEvidence(c, capability.CapabilityEvidence{
				File:       "lockfile",
				Context:    dotnetPkg.Name + "@" + dotnetPkg.Version,
				Via:        "import",
				Confidence: 0.90,
			})
		}
	}
}
