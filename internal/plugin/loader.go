// Package plugin provides gorisk's plugin loading infrastructure.
// Plugins are native Go plugins built with "go build -buildmode=plugin".
// Each plugin .so file must export one or both of:
//   - "CapabilityDetector" (gorisk.CapabilityDetector)
//   - "RiskScorer" (gorisk.RiskScorer)
package plugin

import (
	"fmt"
	"os"
	"path/filepath"
	"plugin"
	"strings"
)

// CapabilityDetector mirrors gorisk.CapabilityDetector to avoid an import cycle.
// Plugins are loaded at runtime; we use the same method signatures.
type CapabilityDetector interface {
	Language() string
	DetectFile(path string) (map[string]float64, error)
}

// RiskScorer mirrors gorisk.RiskScorer.
type RiskScorer interface {
	Name() string
	Score(pkg string, caps []string) float64
}

// LoadedPlugin holds the symbols resolved from a single .so file.
type LoadedPlugin struct {
	Path     string
	Detector CapabilityDetector // nil if not exported
	Scorer   RiskScorer         // nil if not exported
}

// LoadDir loads all .so plugin files from dir.
// Errors for individual files are collected and returned together; valid
// plugins are still returned.
func LoadDir(dir string) ([]LoadedPlugin, []error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, []error{fmt.Errorf("read plugin dir %s: %w", dir, err)}
	}

	var loaded []LoadedPlugin
	var errs []error

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".so") {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		lp, err := Load(path)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		loaded = append(loaded, lp)
	}

	return loaded, errs
}

// Load opens a single plugin .so file and resolves known symbols.
func Load(path string) (LoadedPlugin, error) {
	p, err := plugin.Open(path)
	if err != nil {
		return LoadedPlugin{}, fmt.Errorf("open plugin %s: %w", path, err)
	}

	lp := LoadedPlugin{Path: path}

	// Try to resolve CapabilityDetector.
	if sym, err := p.Lookup("CapabilityDetector"); err == nil {
		if det, ok := sym.(CapabilityDetector); ok {
			lp.Detector = det
		}
	}

	// Try to resolve RiskScorer.
	if sym, err := p.Lookup("RiskScorer"); err == nil {
		if scorer, ok := sym.(RiskScorer); ok {
			lp.Scorer = scorer
		}
	}

	if lp.Detector == nil && lp.Scorer == nil {
		return LoadedPlugin{}, fmt.Errorf("plugin %s exports neither CapabilityDetector nor RiskScorer", filepath.Base(path))
	}

	return lp, nil
}

// PluginDir returns the default directory where gorisk looks for plugins.
// It is $HOME/.gorisk/plugins on Unix and %APPDATA%\gorisk\plugins on Windows.
func PluginDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".gorisk", "plugins")
}
