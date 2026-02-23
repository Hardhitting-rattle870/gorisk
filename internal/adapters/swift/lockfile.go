// Package swift implements a gorisk analyzer for Swift / Swift Package Manager
// (SPM) projects.
package swift

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// SwiftPackage represents a Swift/SPM dependency.
type SwiftPackage struct {
	Name         string
	Version      string
	Direct       bool
	Dependencies []string
}

// Load detects and parses the Swift dependency lockfile in dir.
// Priority: Package.resolved → Package.swift.
// Load never panics; it returns a structured error on failure.
func Load(dir string) (pkgs []SwiftPackage, retErr error) {
	defer func() {
		if r := recover(); r != nil {
			retErr = fmt.Errorf("swift.Load %s: recovered from panic: %v", dir, r)
		}
	}()

	switch {
	case fileExists(filepath.Join(dir, "Package.resolved")):
		return loadPackageResolved(dir)
	case fileExists(filepath.Join(dir, "Package.swift")):
		return loadPackageSwift(dir)
	}
	return nil, fmt.Errorf("no Swift lockfile found (looked for Package.resolved, Package.swift) in %s", dir)
}

// ---------------------------------------------------------------------------
// Package.resolved (v1, v2, v3)
// ---------------------------------------------------------------------------

// resolvedFile is the top-level structure for all Package.resolved versions.
type resolvedFile struct {
	Version int             `json:"version"`
	Pins    []resolvedPinV2 `json:"pins"`   // v2 / v3
	Object  *resolvedObject `json:"object"` // v1
}

type resolvedObject struct {
	Pins []resolvedPinV1 `json:"pins"`
}

// resolvedPinV2 covers both v2 and v3 formats.
type resolvedPinV2 struct {
	Identity string        `json:"identity"`
	Kind     string        `json:"kind"`
	Location string        `json:"location"`
	State    resolvedState `json:"state"`
}

// resolvedPinV1 covers the older nested format.
type resolvedPinV1 struct {
	Package       string        `json:"package"`
	RepositoryURL string        `json:"repositoryURL"`
	State         resolvedState `json:"state"`
}

type resolvedState struct {
	Version  string `json:"version"`
	Revision string `json:"revision"`
	Branch   string `json:"branch"`
}

// loadPackageResolved reads and parses Package.resolved, handling v1/v2/v3.
func loadPackageResolved(dir string) ([]SwiftPackage, error) {
	path := filepath.Join(dir, "Package.resolved")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if len(data) == 0 {
		return nil, nil
	}

	var rf resolvedFile
	if err := json.Unmarshal(data, &rf); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}

	var pkgs []SwiftPackage

	switch rf.Version {
	case 1:
		if rf.Object == nil {
			return nil, nil
		}
		for _, pin := range rf.Object.Pins {
			if pin.Package == "" {
				continue
			}
			pkgs = append(pkgs, SwiftPackage{
				Name:    capitalizeFirst(pin.Package),
				Version: pin.State.Version,
				Direct:  true,
			})
		}
	default:
		// v2, v3 and any future version follow the flat pins format.
		for _, pin := range rf.Pins {
			if pin.Identity == "" {
				continue
			}
			pkgs = append(pkgs, SwiftPackage{
				Name:    capitalizeFirst(pin.Identity),
				Version: pin.State.Version,
				Direct:  true,
			})
		}
	}

	return pkgs, nil
}

// ---------------------------------------------------------------------------
// Package.swift (line-scanner fallback)
// ---------------------------------------------------------------------------

// loadPackageSwift is a minimal line-scanner for Package.swift.
// It looks for .package( lines and extracts names from name: "X" or URL basenames.
func loadPackageSwift(dir string) ([]SwiftPackage, error) {
	path := filepath.Join(dir, "Package.swift")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if len(data) == 0 {
		return nil, nil
	}

	var pkgs []SwiftPackage
	seen := make(map[string]bool)

	lineNo := 0
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		lineNo++
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		if !strings.Contains(trimmed, ".package(") {
			continue
		}

		name := extractPackageSwiftName(trimmed)
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		pkgs = append(pkgs, SwiftPackage{
			Name:   name,
			Direct: true,
		})
	}
	if err := scanner.Err(); err != nil {
		return pkgs, fmt.Errorf("parse %s line %d: %w", path, lineNo, err)
	}

	return pkgs, nil
}

// extractPackageSwiftName extracts a package name from a .package( line.
// It prefers the name: "X" argument; otherwise falls back to the URL basename.
func extractPackageSwiftName(line string) string {
	// Prefer explicit name: "Foo" or name: 'Foo'
	for _, needle := range []string{`name: "`, `name: '`} {
		if _, after, ok := strings.Cut(line, needle); ok {
			quote := needle[len(needle)-1]
			if end := strings.IndexByte(after, quote); end > 0 {
				return after[:end]
			}
		}
	}

	// Fall back to URL basename from url: "..." or from: "..."
	for _, needle := range []string{`url: "`, `url: '`, `from: "`, `from: '`} {
		if _, after, ok := strings.Cut(line, needle); ok {
			quote := needle[len(needle)-1]
			if end := strings.IndexByte(after, quote); end > 0 {
				after = after[:end]
			}
			base := urlBasename(after)
			if base != "" {
				return capitalizeFirst(strings.TrimSuffix(base, ".git"))
			}
		}
	}
	return ""
}

// urlBasename returns the last path segment of a URL string.
func urlBasename(rawURL string) string {
	rawURL = strings.TrimRight(rawURL, "/")
	if idx := strings.LastIndex(rawURL, "/"); idx >= 0 {
		return rawURL[idx+1:]
	}
	return rawURL
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// capitalizeFirst upper-cases the first rune of s, leaving the rest intact.
func capitalizeFirst(s string) string {
	if s == "" {
		return ""
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
