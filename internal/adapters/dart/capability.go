package dart

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"

	"github.com/1homsi/gorisk/internal/capability"
)

// dartPatterns holds the Dart PatternSet loaded from languages/dart.yaml.
var dartPatterns = capability.MustLoadPatterns("dart")

// Detect walks .dart files in dir and returns the combined capability set.
func Detect(dir string) capability.CapabilitySet {
	var caps capability.CapabilitySet

	_ = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info == nil || info.IsDir() {
			return nil
		}
		if strings.ToLower(filepath.Ext(path)) == ".dart" {
			scanDartFile(path, &caps)
		}
		return nil
	})

	return caps
}

// scanDartFile scans a single Dart source file for capability evidence.
func scanDartFile(path string, caps *capability.CapabilitySet) {
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

		// Match import statements.
		if strings.HasPrefix(trimmed, "import ") {
			checkDartImport(line, caps, path, lineNo)
		}

		// Match call-site patterns (substring match).
		for pattern, patCaps := range dartPatterns.CallSites {
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

// checkDartImport detects capabilities from Dart import statements.
// Handles:
//   - import 'package:http/http.dart';   → package name: "http"
//   - import "package:dio/dio.dart";     → package name: "dio"
//   - import 'dart:io';                  → key: "dart:io"
//   - import "dart:isolate";             → key: "dart:isolate"
func checkDartImport(line string, caps *capability.CapabilitySet, path string, lineNo int) {
	trimmed := strings.TrimSpace(line)

	// Strip "import " prefix.
	rest, ok := strings.CutPrefix(trimmed, "import ")
	if !ok {
		return
	}
	rest = strings.TrimSpace(rest)
	// Strip opening quote.
	rest = strings.TrimLeft(rest, `"'`)
	// Take up to closing quote, semicolon, or whitespace.
	if idx := strings.IndexAny(rest, `"';`+"\t "); idx >= 0 {
		rest = rest[:idx]
	}

	var lookupKey string

	if strings.HasPrefix(rest, "dart:") {
		// dart: SDK import — use full scheme as key, e.g. "dart:io".
		lookupKey = rest
	} else if strings.HasPrefix(rest, "package:") {
		// package: import — extract the package name (part before first "/").
		pkgPath, ok2 := strings.CutPrefix(rest, "package:")
		if !ok2 || pkgPath == "" {
			return
		}
		pkgName, _, _ := strings.Cut(pkgPath, "/")
		lookupKey = pkgName
	} else {
		// Relative import — no capability mapping.
		return
	}

	if importCaps, ok := dartPatterns.Imports[lookupKey]; ok {
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
