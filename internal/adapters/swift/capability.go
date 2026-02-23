package swift

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"

	"github.com/1homsi/gorisk/internal/capability"
)

// swiftPatterns holds the Swift PatternSet loaded from languages/swift.yaml.
var swiftPatterns = capability.MustLoadPatterns("swift")

// Detect walks .swift files in dir and returns the combined capability set.
func Detect(dir string) capability.CapabilitySet {
	var caps capability.CapabilitySet

	_ = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info == nil || info.IsDir() {
			return nil
		}
		if strings.ToLower(filepath.Ext(path)) == ".swift" {
			scanSwiftFile(path, &caps)
		}
		return nil
	})

	return caps
}

// scanSwiftFile scans a single Swift source file for capability evidence.
func scanSwiftFile(path string, caps *capability.CapabilitySet) {
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

		// Match "import ModuleName" statements.
		if strings.HasPrefix(trimmed, "import ") {
			checkSwiftImport(line, caps, path, lineNo)
		}

		// Match call-site patterns (substring match).
		for pattern, patCaps := range swiftPatterns.CallSites {
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

// checkSwiftImport detects capabilities from Swift import statements.
func checkSwiftImport(line string, caps *capability.CapabilitySet, path string, lineNo int) {
	trimmed := strings.TrimSpace(line)

	rest, ok := strings.CutPrefix(trimmed, "import ")
	if !ok {
		return
	}
	// Take only the first token (module name); strip inline comments.
	if idx := strings.IndexAny(rest, " \t/"); idx >= 0 {
		rest = rest[:idx]
	}
	moduleName := strings.TrimSpace(rest)
	if moduleName == "" {
		return
	}

	// Try exact name, lowercase variant, and capitalised variant.
	candidates := []string{
		moduleName,
		strings.ToLower(moduleName),
		capitalizeFirst(strings.ToLower(moduleName)),
	}

	for _, candidate := range candidates {
		if importCaps, ok := swiftPatterns.Imports[candidate]; ok {
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
