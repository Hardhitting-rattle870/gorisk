// Package dart implements a gorisk analyzer for Dart/Flutter projects.
// It supports pubspec.lock and pubspec.yaml.
package dart

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// DartPackage represents a Dart/Flutter dependency.
type DartPackage struct {
	Name         string
	Version      string
	Direct       bool
	Dependencies []string
}

// Load detects and parses the Dart dependency lockfile in dir.
// Priority: pubspec.lock → pubspec.yaml
// Load never panics; it returns a structured error on failure.
func Load(dir string) (pkgs []DartPackage, retErr error) {
	defer func() {
		if r := recover(); r != nil {
			retErr = fmt.Errorf("dart.Load %s: recovered from panic: %v", dir, r)
		}
	}()

	switch {
	case fileExists(filepath.Join(dir, "pubspec.lock")):
		return loadPubspecLock(dir)
	case fileExists(filepath.Join(dir, "pubspec.yaml")):
		return loadPubspecYAML(dir)
	}
	return nil, fmt.Errorf("no Dart lockfile found (looked for pubspec.lock, pubspec.yaml) in %s", dir)
}

// ---------------------------------------------------------------------------
// pubspec.lock
// ---------------------------------------------------------------------------

// pubspec.lock uses YAML. We parse it with a line-oriented state machine.
//
// Top-level structure:
//
//	packages:          ← indent 0, key = "packages", value = ""
//	  http:            ← indent 2, package name
//	    dependency: "direct main"   ← indent 4
//	    description:   ← indent 4, starts a sub-block (value = "")
//	      name: http   ← indent 6, inside description (ignored)
//	      sha256: "…"  ← indent 6
//	      url: "…"     ← indent 6
//	    source: hosted ← indent 4
//	    version: "1.2.1"  ← indent 4
//	sdks:              ← indent 0, not "packages:" — end of packages block
func loadPubspecLock(dir string) ([]DartPackage, error) {
	path := filepath.Join(dir, "pubspec.lock")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if len(data) == 0 {
		return nil, nil
	}

	var packages []DartPackage
	// cur accumulates fields for the package currently being parsed.
	var curName string
	var curVersion string
	var curDirect bool
	var curDeps []string

	// inPackages: we are inside the "packages:" block.
	inPackages := false
	// curPkgIndent: the indent level of the current package name (typically 2).
	// depSectionIndent: if >= 0, we are inside a "dependencies:" sub-block.
	depSectionIndent := -1

	flushCurrent := func() {
		if curName == "" {
			return
		}
		packages = append(packages, DartPackage{
			Name:         curName,
			Version:      curVersion,
			Direct:       curDirect,
			Dependencies: curDeps,
		})
		curName = ""
		curVersion = ""
		curDirect = false
		curDeps = nil
		depSectionIndent = -1
	}

	lineNo := 0
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		lineNo++
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		// Skip blank lines and comments.
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		indent := leadingSpaces(line)

		// Top-level key (indent 0).
		if indent == 0 {
			flushCurrent()
			inPackages = false
			key, _, _ := strings.Cut(trimmed, ":")
			if strings.TrimSpace(key) == "packages" {
				inPackages = true
			}
			continue
		}

		if !inPackages {
			continue
		}

		// Package name line (indent 2, key with empty value).
		if indent == 2 {
			flushCurrent()
			name, val, ok := strings.Cut(trimmed, ":")
			if ok {
				val = strings.TrimSpace(val)
				val = strings.Trim(val, `"'`)
				// A package name line has an empty value after the colon.
				if val == "" {
					curName = strings.TrimSpace(name)
					depSectionIndent = -1
				}
			}
			continue
		}

		if curName == "" {
			continue
		}

		// Package field lines (indent 4) or deeper.
		if indent == 4 {
			// Leaving a dependencies sub-section.
			depSectionIndent = -1

			key, val, ok := strings.Cut(trimmed, ":")
			if !ok {
				continue
			}
			key = strings.TrimSpace(key)
			val = strings.TrimSpace(val)
			val = strings.Trim(val, `"'`)

			switch key {
			case "dependency":
				// "direct main" | "direct dev" | "transitive"
				curDirect = strings.HasPrefix(val, "direct")
			case "version":
				curVersion = val
			case "dependencies":
				// Sub-section: dependencies of this package.
				depSectionIndent = 4
			}
			continue
		}

		// Indent 6+: sub-fields (inside description, dependencies, etc.)
		if indent >= 6 && depSectionIndent >= 0 {
			// We are inside a "dependencies:" sub-section.
			depName, _, _ := strings.Cut(trimmed, ":")
			depName = strings.TrimSpace(depName)
			if depName != "" && !strings.HasPrefix(depName, "-") {
				curDeps = append(curDeps, depName)
			}
		}
		// indent >= 6 inside description block — ignore.
	}

	// Flush the last package.
	flushCurrent()

	if err := scanner.Err(); err != nil {
		return packages, fmt.Errorf("parse %s line %d: %w", path, lineNo, err)
	}

	return packages, nil
}

// ---------------------------------------------------------------------------
// pubspec.yaml (fallback — no lockfile)
// ---------------------------------------------------------------------------

// loadPubspecYAML parses pubspec.yaml for dependency declarations.
// Handles dependencies: and dev_dependencies: sections.
// All packages are considered Direct=true.
func loadPubspecYAML(dir string) ([]DartPackage, error) {
	path := filepath.Join(dir, "pubspec.yaml")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if len(data) == 0 {
		return nil, nil
	}

	var packages []DartPackage
	seen := make(map[string]bool)

	inDepsSection := false

	lineNo := 0
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		lineNo++
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		indent := leadingSpaces(line)

		// Top-level section headers.
		if indent == 0 {
			inDepsSection = trimmed == "dependencies:" || trimmed == "dev_dependencies:"
			continue
		}

		if !inDepsSection {
			continue
		}

		// Package entries are at 2-space indent.
		if indent == 2 {
			name, constraint, ok := strings.Cut(trimmed, ":")
			name = strings.TrimSpace(name)
			if !ok || name == "" || strings.HasPrefix(name, "-") {
				continue
			}
			// Skip non-package entries.
			if name == "sdk" || name == "flutter" {
				continue
			}

			version := ""
			if ok {
				constraint = strings.TrimSpace(constraint)
				constraint = strings.Trim(constraint, `"'`)
				// Strip semver constraint operators.
				for _, op := range []string{"^", ">=", "<=", "!=", "~", ">", "<", "="} {
					constraint, _ = strings.CutPrefix(constraint, op)
				}
				version = strings.TrimSpace(constraint)
			}

			if !seen[name] {
				seen[name] = true
				packages = append(packages, DartPackage{
					Name:    name,
					Version: version,
					Direct:  true,
				})
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return packages, fmt.Errorf("parse %s line %d: %w", path, lineNo, err)
	}

	return packages, nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// leadingSpaces counts the number of leading spaces in a line.
// Tabs count as 2 spaces to handle YAML indentation.
func leadingSpaces(line string) int {
	count := 0
	for _, ch := range line {
		switch ch {
		case ' ':
			count++
		case '\t':
			count += 2
		default:
			return count
		}
	}
	return count
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
