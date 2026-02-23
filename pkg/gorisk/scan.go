package gorisk

import (
	"fmt"
	"os"
	"sort"

	"github.com/1homsi/gorisk/internal/analyzer"
	"github.com/1homsi/gorisk/internal/astpipeline"
	"github.com/1homsi/gorisk/internal/capability"
	"github.com/1homsi/gorisk/internal/priority"
	"github.com/1homsi/gorisk/internal/taint"
)

// ScanOptions configures a Scanner invocation.
type ScanOptions struct {
	// Dir is the project root to scan. Defaults to os.Getwd().
	Dir string
	// Lang is the language hint: "auto", "go", "node", "python", etc.
	// Defaults to "auto".
	Lang string
	// Policy drives enforcement. Defaults to DefaultPolicy().
	Policy Policy
}

// Scanner analyses a project directory for dependency risk.
type Scanner struct {
	opts ScanOptions
}

// NewScanner returns a Scanner configured with opts.
// Missing fields in opts are filled with safe defaults.
func NewScanner(opts ScanOptions) *Scanner {
	if opts.Dir == "" {
		opts.Dir, _ = os.Getwd()
	}
	if opts.Lang == "" {
		opts.Lang = "auto"
	}
	if opts.Policy.FailOn == "" {
		opts.Policy = DefaultPolicy()
	}
	return &Scanner{opts: opts}
}

// Scan performs the full risk analysis pipeline and returns a ScanResult.
func (s *Scanner) Scan() (*ScanResult, error) {
	dir := s.opts.Dir
	lang := s.opts.Lang

	a, err := analyzer.ForLang(lang, dir)
	if err != nil {
		return nil, err
	}

	g, err := a.Load(dir)
	if err != nil {
		return nil, err
	}

	// Sort package keys for deterministic output.
	pkgKeys := make([]string, 0, len(g.Packages))
	for k := range g.Packages {
		pkgKeys = append(pkgKeys, k)
	}
	sort.Strings(pkgKeys)

	// AST interprocedural pipeline + taint analysis.
	resolvedLang := analyzer.ResolveLang(lang, dir)
	astResult := astpipeline.Analyze(dir, resolvedLang, g)
	taintFindings := taint.Analyze(g.Packages)
	if astResult.UsedInterproc && len(astResult.Bundle.TaintFindings) > 0 {
		taintFindings = astResult.Bundle.TaintFindings
	}

	failLevel := capability.RiskValue(s.opts.Policy.FailOn)

	result := &ScanResult{
		SchemaVersion: "v1",
		Passed:        true,
	}

	for _, pkgKey := range pkgKeys {
		pkg := g.Packages[pkgKey]
		if pkg == nil {
			continue
		}

		var reachable *bool
		if astResult.UsedInterproc {
			v := astResult.Bundle.ReachabilityHints[pkgKey]
			reachable = &v
		}

		finalScore := priority.ComputeFinal(
			pkg.Capabilities,
			reachable,
			nil, // per-package taint slice (unused for SDK basic path)
			0,   // diffScore
			0,   // integScore
			0,   // topoScore
		)

		modPath := ""
		if pkg.Module != nil {
			modPath = pkg.Module.Path
		}

		result.Findings = append(result.Findings, Finding{
			Package:      pkg.ImportPath,
			Module:       modPath,
			Capabilities: pkg.Capabilities.List(),
			Risk:         RiskLevel(finalScore.Level),
			Score:        finalScore.Final,
		})

		if result.Passed && capability.RiskValue(finalScore.Level) >= failLevel {
			result.Passed = false
			result.FailReason = fmt.Sprintf("package %s has %s risk (score: %.1f)", pkgKey, finalScore.Level, finalScore.Final)
		}
	}

	for _, tf := range taintFindings {
		result.TaintFlows = append(result.TaintFlows, TaintFinding{
			Package:    tf.Package,
			Module:     tf.Module,
			Source:     string(tf.Source),
			Sink:       string(tf.Sink),
			Risk:       RiskLevel(tf.Risk),
			Note:       tf.Note,
			Confidence: tf.Confidence,
		})
	}

	return result, nil
}
