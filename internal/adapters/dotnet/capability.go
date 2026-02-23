package dotnet

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"

	"github.com/1homsi/gorisk/internal/capability"
)

// dotnetPatterns holds the .NET PatternSet loaded from languages/dotnet.yaml.
var dotnetPatterns = capability.MustLoadPatterns("dotnet")

// Detect walks .cs files in dir and returns the combined capability set.
func Detect(dir string) capability.CapabilitySet {
	var caps capability.CapabilitySet

	_ = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info == nil || info.IsDir() {
			return nil
		}
		if strings.ToLower(filepath.Ext(path)) == ".cs" {
			scanCSFile(path, &caps)
		}
		return nil
	})

	return caps
}

// scanCSFile scans a single C# source file for capability evidence.
func scanCSFile(path string, caps *capability.CapabilitySet) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)

	lineNo := 0
	for scanner.Scan() {
		line := scanner.Text()
		lineNo++

		trimmed := strings.TrimSpace(line)

		// Match "using X.Y.Z;" statements.
		if strings.HasPrefix(trimmed, "using ") {
			checkDotnetImport(line, caps, path, lineNo)
			// Don't skip call_site scan; line may also match a call site.
		}

		// Match call-site patterns (substring match).
		for pattern, patCaps := range dotnetPatterns.CallSites {
			if strings.Contains(line, pattern) {
				for _, c := range patCaps {
					caps.AddWithEvidence(c, capability.CapabilityEvidence{
						File:       path,
						Line:       lineNo,
						Context:    strings.TrimSpace(line),
						Via:        "callSite",
						Confidence: 0.75,
					})
				}
			}
		}
	}
}

// checkDotnetImport detects capabilities from C# "using X.Y.Z;" statements.
// Uses longest-prefix matching against the dotnet patterns import map.
func checkDotnetImport(line string, caps *capability.CapabilitySet, path string, lineNo int) {
	trimmed := strings.TrimSpace(line)

	rest, ok := strings.CutPrefix(trimmed, "using ")
	if !ok {
		return
	}
	// Strip optional "static " or "global::" modifiers.
	rest, _ = strings.CutPrefix(rest, "static ")
	rest, _ = strings.CutPrefix(rest, "global::")
	// Strip trailing semicolon and whitespace.
	namespaceName := strings.TrimRight(strings.TrimSpace(rest), ";")
	// Strip alias assignment: "using Alias = X.Y.Z" → "X.Y.Z"
	if _, after, hasCut := strings.Cut(namespaceName, "="); hasCut {
		namespaceName = strings.TrimSpace(after)
	}
	if namespaceName == "" {
		return
	}

	if importCaps := longestPrefixMatch(namespaceName); len(importCaps) > 0 {
		for _, c := range importCaps {
			caps.AddWithEvidence(c, capability.CapabilityEvidence{
				File:       path,
				Line:       lineNo,
				Context:    strings.TrimSpace(line),
				Via:        "import",
				Confidence: 0.90,
			})
		}
	}
}

// longestPrefixMatch finds the most specific (longest) matching import pattern
// for the given namespace name. It tries progressively shorter dot-delimited
// prefixes until it finds a match in dotnetPatterns.Imports.
func longestPrefixMatch(namespaceName string) []capability.Capability {
	parts := strings.Split(namespaceName, ".")
	for i := len(parts); i >= 1; i-- {
		prefix := strings.Join(parts[:i], ".")
		if importCaps, ok := dotnetPatterns.Imports[prefix]; ok {
			return importCaps
		}
	}
	return nil
}
