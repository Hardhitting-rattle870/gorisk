// Package elixir implements a gorisk analyzer for Elixir/Erlang projects.
// It supports mix.lock and mix.exs.
package elixir

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ElixirPackage represents an Elixir/Hex dependency.
type ElixirPackage struct {
	Name         string
	Version      string
	Direct       bool
	Dependencies []string
}

// Load detects and parses the Elixir dependency lockfile in dir.
// Priority: mix.lock -> mix.exs
// Load never panics; it returns a structured error on failure.
func Load(dir string) (pkgs []ElixirPackage, retErr error) {
	defer func() {
		if r := recover(); r != nil {
			retErr = fmt.Errorf("elixir.Load %s: recovered from panic: %v", dir, r)
		}
	}()

	switch {
	case fileExists(filepath.Join(dir, "mix.lock")):
		return loadMixLock(dir)
	case fileExists(filepath.Join(dir, "mix.exs")):
		return loadMixExs(dir)
	}
	return nil, fmt.Errorf("no Elixir lockfile found (looked for mix.lock, mix.exs) in %s", dir)
}

// ---------------------------------------------------------------------------
// mix.lock
// ---------------------------------------------------------------------------

// mix.lock format (one dependency per line):
//
//	%{
//	  "bcrypt_elixir": {:hex, :bcrypt_elixir, "3.0.1", "sha512:...", [:mix], [{:comeonin, "~> 5.3", [...]}, ...], "hexpm", "..."},
//	  "certifi": {:hex, :certifi, "2.12.0", "...", [:rebar3], [], "hexpm", "..."},
//	}
//
// Parse strategy:
//   - Each dependency line starts with two-space indentation followed by `"name":`.
//   - Version is the third quoted string on the line.
//   - Dependency names are extracted by scanning for `{:dep_name,` patterns in
//     the deps list section of the line.
func loadMixLock(dir string) ([]ElixirPackage, error) {
	path := filepath.Join(dir, "mix.lock")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if len(data) == 0 {
		return nil, nil
	}

	var packages []ElixirPackage
	byName := make(map[string]*ElixirPackage)

	lineNo := 0
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		lineNo++
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		// Skip map delimiters and blank lines.
		if trimmed == "" || trimmed == "%{" || trimmed == "}" {
			continue
		}

		name, version, deps := parseMixLockLine(trimmed)
		if name == "" {
			continue
		}

		pkg := ElixirPackage{
			Name:         name,
			Version:      version,
			Direct:       false,
			Dependencies: deps,
		}
		packages = append(packages, pkg)
	}
	if err := scanner.Err(); err != nil {
		return packages, fmt.Errorf("parse %s line %d: %w", path, lineNo, err)
	}

	// Rebuild byName using final slice addresses (safe after all appends).
	for i := range packages {
		byName[packages[i].Name] = &packages[i]
	}

	// Mark direct deps from mix.exs.
	markDirectDeps(dir, byName)

	return packages, nil
}

// parseMixLockLine extracts name, version, and dependency names from a single
// mix.lock entry line such as:
//
//	"bcrypt_elixir": {:hex, :bcrypt_elixir, "3.0.1", "hash", [:mix], [{:comeonin, ...}], "hexpm", "..."},
func parseMixLockLine(line string) (name, version string, deps []string) {
	// Extract package name — first quoted string before the colon.
	afterOpen, rest, ok := strings.Cut(line, `"`)
	if !ok {
		return "", "", nil
	}
	_ = afterOpen
	namePart, rest, ok := strings.Cut(rest, `"`)
	if !ok || namePart == "" {
		return "", "", nil
	}
	name = namePart

	// The line continues with: : {:hex, :name, "version", ...}
	// Find the third quoted string — that's the version.
	quoteCount := 0
	versionStart := -1
	versionEnd := -1
	for i := 0; i < len(rest); i++ {
		if rest[i] == '"' {
			quoteCount++
			if quoteCount == 1 {
				versionStart = i + 1
			} else if quoteCount == 2 {
				versionEnd = i
				break
			}
		}
	}
	if versionStart >= 0 && versionEnd > versionStart {
		version = rest[versionStart:versionEnd]
	}

	// Extract dependency names from patterns like {:dep_name, ...}.
	// The deps list is inside [...] after the managers list.
	// We scan for all occurrences of `{:word,` in the remainder of the line.
	deps = extractDepNames(rest)

	return name, version, deps
}

// extractDepNames finds all {:atom, patterns in s and returns the atom names.
// Used to extract dependency names from the mix.lock deps list.
func extractDepNames(s string) []string {
	var deps []string
	remaining := s
	for {
		idx := strings.Index(remaining, "{:")
		if idx < 0 {
			break
		}
		after := remaining[idx+2:]
		// Take up to the next comma, space, or closing brace.
		end := strings.IndexAny(after, ", }")
		if end < 0 {
			break
		}
		dep := after[:end]
		if dep != "" {
			deps = append(deps, dep)
		}
		remaining = remaining[idx+2:]
	}
	return deps
}

// ---------------------------------------------------------------------------
// mix.exs
// ---------------------------------------------------------------------------

// loadMixExs parses mix.exs for dependency declarations in the deps/0 function.
// Lines inside deps/0 look like:
//
//	{:httpoison, "~> 1.8"},
//	{:ecto, ">= 0.0.0", only: :test},
func loadMixExs(dir string) ([]ElixirPackage, error) {
	path := filepath.Join(dir, "mix.exs")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if len(data) == 0 {
		return nil, nil
	}

	var packages []ElixirPackage
	seen := make(map[string]bool)

	inDeps := false
	lineNo := 0
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		lineNo++
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		// Detect entering the deps function.
		if strings.Contains(trimmed, "defp deps") || strings.Contains(trimmed, "def deps") {
			inDeps = true
			continue
		}

		// Detect leaving the deps function (closing end keyword at same indent).
		if inDeps && (trimmed == "end" || strings.HasPrefix(trimmed, "end ")) {
			inDeps = false
			continue
		}

		if !inDeps {
			continue
		}

		name, version := parseMixExsDepLine(trimmed)
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		packages = append(packages, ElixirPackage{
			Name:    name,
			Version: version,
			Direct:  true,
		})
	}
	if err := scanner.Err(); err != nil {
		return packages, fmt.Errorf("parse %s line %d: %w", path, lineNo, err)
	}

	return packages, nil
}

// parseMixExsDepLine extracts name and optional version from a mix.exs dep line.
// Handles: {:name, "~> 1.0"}, {:name, ">= 0.0.0", only: :test}
func parseMixExsDepLine(line string) (name, version string) {
	// Must start with {: to be a dep tuple.
	rest, ok := strings.CutPrefix(line, "{:")
	if !ok {
		return "", ""
	}

	// Name ends at the next comma or closing brace.
	end := strings.IndexAny(rest, ",}")
	if end < 0 {
		return "", ""
	}
	name = strings.TrimSpace(rest[:end])
	if name == "" {
		return "", ""
	}

	// Version is the first quoted string after the name.
	after := rest[end:]
	vStart := strings.Index(after, `"`)
	if vStart < 0 {
		return name, ""
	}
	after = after[vStart+1:]
	vEnd := strings.Index(after, `"`)
	if vEnd < 0 {
		return name, ""
	}
	ver := after[:vEnd]
	// Strip constraint operators.
	for _, op := range []string{"~> ", ">= ", "<= ", "!= ", "== ", "> ", "< "} {
		ver, _ = strings.CutPrefix(ver, op)
	}
	return name, strings.TrimSpace(ver)
}

// ---------------------------------------------------------------------------
// Direct dep detection
// ---------------------------------------------------------------------------

// markDirectDeps reads mix.exs and marks the matching packages as Direct.
func markDirectDeps(dir string, byName map[string]*ElixirPackage) {
	path := filepath.Join(dir, "mix.exs")
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}

	inDeps := false
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if strings.Contains(line, "defp deps") || strings.Contains(line, "def deps") {
			inDeps = true
			continue
		}
		if inDeps && (line == "end" || strings.HasPrefix(line, "end ")) {
			inDeps = false
			continue
		}
		if !inDeps {
			continue
		}

		name, _ := parseMixExsDepLine(line)
		if name != "" {
			if pkg, ok := byName[name]; ok {
				pkg.Direct = true
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
