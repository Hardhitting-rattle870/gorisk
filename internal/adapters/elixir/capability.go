package elixir

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"

	"github.com/1homsi/gorisk/internal/capability"
)

// elixirPatterns holds the Elixir PatternSet loaded from languages/elixir.yaml.
var elixirPatterns = capability.MustLoadPatterns("elixir")

// Detect walks .ex and .exs files in dir and returns the combined capability set.
func Detect(dir string) capability.CapabilitySet {
	var caps capability.CapabilitySet

	_ = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info == nil || info.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext == ".ex" || ext == ".exs" {
			scanElixirFile(path, &caps)
		}
		return nil
	})

	return caps
}

// scanElixirFile scans a single Elixir source file for capability evidence.
func scanElixirFile(path string, caps *capability.CapabilitySet) {
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

		// Match import/use/alias/require statements.
		if strings.HasPrefix(trimmed, "import ") ||
			strings.HasPrefix(trimmed, "use ") ||
			strings.HasPrefix(trimmed, "alias ") ||
			strings.HasPrefix(trimmed, "require ") {
			checkElixirImport(line, caps, path, lineNo)
		}

		// Match call-site patterns (substring match).
		for pattern, patCaps := range elixirPatterns.CallSites {
			if strings.Contains(line, pattern) {
				for _, c := range patCaps {
					caps.AddWithEvidence(c, capability.CapabilityEvidence{
						File:       path,
						Line:       lineNo,
						Context:    trimmed,
						Via:        "callSite",
						Confidence: 0.75,
					})
				}
			}
		}
	}
}

// checkElixirImport detects capabilities from Elixir import/use/alias/require.
func checkElixirImport(line string, caps *capability.CapabilitySet, path string, lineNo int) {
	trimmed := strings.TrimSpace(line)

	var modName string
	for _, prefix := range []string{"use ", "import ", "alias ", "require "} {
		rest, ok := strings.CutPrefix(trimmed, prefix)
		if !ok {
			continue
		}
		// Strip any trailing options like ", only: [...]" or ", as: Foo".
		if idx := strings.Index(rest, ","); idx >= 0 {
			rest = rest[:idx]
		}
		// Strip inline comments.
		if idx := strings.Index(rest, "#"); idx >= 0 {
			rest = rest[:idx]
		}
		modName = strings.TrimSpace(rest)
		break
	}

	if modName == "" {
		return
	}

	// Use top-level module component for matching (e.g. "Phoenix.Controller" -> "phoenix").
	topLevel := modName
	if dot := strings.Index(modName, "."); dot >= 0 {
		topLevel = modName[:dot]
	}

	candidates := []string{
		strings.ToLower(topLevel),
		strings.ToLower(modName),
		strings.ToLower(strings.ReplaceAll(modName, ".", "_")),
		strings.ToLower(strings.ReplaceAll(modName, ".", "-")),
	}

	for _, candidate := range candidates {
		if importCaps, ok := elixirPatterns.Imports[candidate]; ok {
			for _, c := range importCaps {
				caps.AddWithEvidence(c, capability.CapabilityEvidence{
					File:       path,
					Line:       lineNo,
					Context:    strings.TrimSpace(line),
					Via:        "import",
					Confidence: 0.90,
				})
			}
			return
		}
	}
}
