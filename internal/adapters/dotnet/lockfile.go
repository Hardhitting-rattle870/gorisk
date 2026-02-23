package dotnet

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// DotnetPackage represents a .NET dependency.
type DotnetPackage struct {
	Name         string
	Version      string
	Direct       bool
	Dependencies []string
}

// Load detects and parses the .NET dependency lockfile in dir.
// Priority: packages.lock.json → *.csproj → *.sln (glob for csproj files).
// Load never panics; it returns a structured error on failure.
func Load(dir string) (pkgs []DotnetPackage, retErr error) {
	defer func() {
		if r := recover(); r != nil {
			retErr = fmt.Errorf("dotnet.Load %s: recovered from panic: %v", dir, r)
		}
	}()

	switch {
	case fileExists(filepath.Join(dir, "packages.lock.json")):
		return loadPackagesLockJSON(dir)
	default:
		// Glob for *.csproj files in dir (top-level only).
		matches, err := filepath.Glob(filepath.Join(dir, "*.csproj"))
		if err != nil {
			return nil, fmt.Errorf("glob *.csproj in %s: %w", dir, err)
		}
		if len(matches) > 0 {
			return loadCsproj(matches[0])
		}
	}
	return nil, fmt.Errorf("no .NET lockfile found (looked for packages.lock.json, *.csproj) in %s", dir)
}

// ---------------------------------------------------------------------------
// packages.lock.json (NuGet v2 lock format)
// ---------------------------------------------------------------------------

// packagesLockJSON mirrors the top-level structure of packages.lock.json.
type packagesLockJSON struct {
	Version      int                                    `json:"version"`
	Dependencies map[string]map[string]packageLockEntry `json:"dependencies"`
}

// packageLockEntry mirrors a single package entry inside a target framework.
type packageLockEntry struct {
	Type         string            `json:"type"`
	Requested    string            `json:"requested"`
	Resolved     string            `json:"resolved"`
	ContentHash  string            `json:"contentHash"`
	Dependencies map[string]string `json:"dependencies"`
}

func loadPackagesLockJSON(dir string) ([]DotnetPackage, error) {
	path := filepath.Join(dir, "packages.lock.json")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if len(data) == 0 {
		return nil, nil
	}

	var lock packagesLockJSON
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}

	// Merge packages across all target frameworks; deduplicate by name.
	seen := make(map[string]*DotnetPackage)
	var ordered []string // preserve insertion order for determinism

	for _, frameworkPkgs := range lock.Dependencies {
		for pkgName, entry := range frameworkPkgs {
			if existing, ok := seen[pkgName]; ok {
				// Upgrade Direct flag if seen as Direct in any framework.
				if strings.EqualFold(entry.Type, "Direct") {
					existing.Direct = true
				}
				continue
			}

			pkg := &DotnetPackage{
				Name:    pkgName,
				Version: entry.Resolved,
				Direct:  strings.EqualFold(entry.Type, "Direct"),
			}
			for depName := range entry.Dependencies {
				pkg.Dependencies = append(pkg.Dependencies, depName)
			}
			seen[pkgName] = pkg
			ordered = append(ordered, pkgName)
		}
	}

	pkgs := make([]DotnetPackage, 0, len(ordered))
	for _, name := range ordered {
		pkgs = append(pkgs, *seen[name])
	}
	return pkgs, nil
}

// ---------------------------------------------------------------------------
// *.csproj (XML fallback)
// ---------------------------------------------------------------------------

// csprojProject mirrors the relevant portion of a .csproj XML file.
type csprojProject struct {
	XMLName    xml.Name          `xml:"Project"`
	ItemGroups []csprojItemGroup `xml:"ItemGroup"`
}

// csprojItemGroup mirrors a single <ItemGroup> element.
type csprojItemGroup struct {
	PackageReferences []csprojPackageRef `xml:"PackageReference"`
}

// csprojPackageRef mirrors a single <PackageReference> element.
type csprojPackageRef struct {
	Include string `xml:"Include,attr"`
	Version string `xml:"Version,attr"`
}

func loadCsproj(path string) ([]DotnetPackage, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if len(data) == 0 {
		return nil, nil
	}

	var proj csprojProject
	if err := xml.Unmarshal(data, &proj); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}

	seen := make(map[string]bool)
	var pkgs []DotnetPackage
	for _, ig := range proj.ItemGroups {
		for _, ref := range ig.PackageReferences {
			if ref.Include == "" || seen[ref.Include] {
				continue
			}
			seen[ref.Include] = true
			pkgs = append(pkgs, DotnetPackage{
				Name:    ref.Include,
				Version: ref.Version,
				Direct:  true,
			})
		}
	}
	return pkgs, nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
