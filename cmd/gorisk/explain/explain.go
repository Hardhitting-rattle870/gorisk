package explain

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/1homsi/gorisk/internal/analyzer"
	"github.com/1homsi/gorisk/internal/astpipeline"
	"github.com/1homsi/gorisk/internal/capability"
	"github.com/1homsi/gorisk/internal/report"
	"github.com/1homsi/gorisk/internal/taint"
)

type evidenceEntry struct {
	Package    string
	Module     string
	Capability string
	Evidence   []capability.CapabilityEvidence
	Score      int
}

func Run(args []string) int {
	fs := flag.NewFlagSet("explain", flag.ExitOnError)
	capFilter := fs.String("cap", "", "filter to a specific capability (e.g. exec, network)")
	jsonOut := fs.Bool("json", false, "JSON output")
	lang := fs.String("lang", "auto", "language analyzer: auto|go|node")
	fs.Parse(args)

	dir, err := os.Getwd()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}

	a, err := analyzer.ForLang(*lang, dir)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	g, err := a.Load(dir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "load graph:", err)
		return 2
	}

	var entries []evidenceEntry
	for _, pkg := range g.Packages {
		if pkg.Module == nil || pkg.Module.Main {
			continue
		}
		for _, cap := range pkg.Capabilities.List() {
			if *capFilter != "" && cap != *capFilter {
				continue
			}
			evs := pkg.Capabilities.Evidence[cap]
			entries = append(entries, evidenceEntry{
				Package:    pkg.ImportPath,
				Module:     pkg.Module.Path,
				Capability: cap,
				Evidence:   evs,
				Score:      pkg.Capabilities.Score,
			})
		}
	}

	// Sort by module first, then by score descending, then capability, then package.
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Module != entries[j].Module {
			return entries[i].Module < entries[j].Module
		}
		if entries[i].Score != entries[j].Score {
			return entries[i].Score > entries[j].Score
		}
		if entries[i].Capability != entries[j].Capability {
			return entries[i].Capability < entries[j].Capability
		}
		return entries[i].Package < entries[j].Package
	})

	resolvedLang := analyzer.ResolveLang(*lang, dir)
	astResult := astpipeline.Analyze(dir, resolvedLang, g)
	taintFindings := taint.Analyze(g.Packages)
	if astResult.UsedInterproc && len(astResult.Bundle.TaintFindings) > 0 {
		taintFindings = astResult.Bundle.TaintFindings
	}
	if *capFilter != "" {
		filtered := taintFindings[:0:0]
		for _, tf := range taintFindings {
			if string(tf.Source) == *capFilter || string(tf.Sink) == *capFilter {
				filtered = append(filtered, tf)
			}
		}
		taintFindings = filtered
	}

	if *jsonOut {
		return printJSONWithTaint(entries, taintFindings)
	}
	report.WriteTaintFindings(os.Stdout, taintFindings)
	return printText(entries, dir)
}

func printJSONWithTaint(entries []evidenceEntry, taintFindings []taint.TaintFinding) int {
	type jsonEv struct {
		File       string  `json:"file"`
		Line       int     `json:"line,omitempty"`
		Context    string  `json:"context,omitempty"`
		Via        string  `json:"via,omitempty"`
		Confidence float64 `json:"confidence,omitempty"`
	}
	type jsonEntry struct {
		Package    string   `json:"package"`
		Module     string   `json:"module"`
		Capability string   `json:"capability"`
		Score      int      `json:"score,omitempty"`
		Evidence   []jsonEv `json:"evidence"`
	}
	type jsonOutput struct {
		Capabilities  []jsonEntry          `json:"capabilities"`
		TaintFindings []taint.TaintFinding `json:"taint_findings,omitempty"`
	}

	capEntries := make([]jsonEntry, 0, len(entries))
	for _, e := range entries {
		jevs := make([]jsonEv, 0, len(e.Evidence))
		for _, ev := range e.Evidence {
			jevs = append(jevs, jsonEv{
				File:       ev.File,
				Line:       ev.Line,
				Context:    ev.Context,
				Via:        ev.Via,
				Confidence: ev.Confidence,
			})
		}
		capEntries = append(capEntries, jsonEntry{
			Package:    e.Package,
			Module:     e.Module,
			Capability: e.Capability,
			Score:      e.Score,
			Evidence:   jevs,
		})
	}
	if capEntries == nil {
		capEntries = []jsonEntry{}
	}

	out := jsonOutput{
		Capabilities:  capEntries,
		TaintFindings: taintFindings,
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.Encode(out)
	return 0
}

func printText(entries []evidenceEntry, cwd string) int {
	const (
		bold   = "\033[1m"
		cyan   = "\033[36m"
		yellow = "\033[33m"
		red    = "\033[31m"
		green  = "\033[32m"
		gray   = "\033[90m"
		reset  = "\033[0m"
	)

	if len(entries) == 0 {
		fmt.Println("no capabilities found")
		return 0
	}

	fmt.Fprintf(os.Stdout, "%s%s=== Capability Evidence ===%s\n\n", bold, cyan, reset)

	// Group by module, preserving insertion order (entries already sorted by module).
	type capEntry struct {
		capability string
		score      int
		pkgEntries []evidenceEntry
	}
	type modGroup struct {
		caps  map[string]*capEntry
		order []string // capability insertion order within module
	}
	modGroups := make(map[string]*modGroup)
	modOrder := []string{}

	for _, e := range entries {
		if _, ok := modGroups[e.Module]; !ok {
			modGroups[e.Module] = &modGroup{caps: make(map[string]*capEntry)}
			modOrder = append(modOrder, e.Module)
		}
		mg := modGroups[e.Module]
		if _, exists := mg.caps[e.Capability]; !exists {
			mg.caps[e.Capability] = &capEntry{capability: e.Capability, score: e.Score}
			mg.order = append(mg.order, e.Capability)
		}
		ce := mg.caps[e.Capability]
		// Keep highest score seen for this capability group.
		if e.Score > ce.score {
			ce.score = e.Score
		}
		ce.pkgEntries = append(ce.pkgEntries, e)
	}

	// Sort capabilities within each module by score descending, then name.
	for _, mg := range modGroups {
		sort.Slice(mg.order, func(i, j int) bool {
			ci := mg.caps[mg.order[i]]
			cj := mg.caps[mg.order[j]]
			if ci.score != cj.score {
				return ci.score > cj.score
			}
			return mg.order[i] < mg.order[j]
		})
	}

	for _, modPath := range modOrder {
		mg := modGroups[modPath]

		// Compute aggregate score for the module (max across capabilities).
		maxScore := 0
		for _, ce := range mg.caps {
			if ce.score > maxScore {
				maxScore = ce.score
			}
		}

		scoreColor := green
		riskLabel := "LOW"
		switch {
		case maxScore >= 30:
			scoreColor = red
			riskLabel = "HIGH"
		case maxScore >= 10:
			scoreColor = yellow
			riskLabel = "MEDIUM"
		}

		fmt.Fprintf(os.Stdout, "%s%s%s  %s[score:%d %s]%s\n",
			bold, modPath, reset,
			scoreColor, maxScore, riskLabel, reset)

		for _, capName := range mg.order {
			ce := mg.caps[capName]
			fmt.Fprintf(os.Stdout, "  %s%s%s\n", cyan, capName, reset)

			for _, entry := range ce.pkgEntries {
				fmt.Fprintf(os.Stdout, "    %s%s%s\n", gray, entry.Package, reset)

				if len(entry.Evidence) == 0 {
					fmt.Fprintf(os.Stdout, "      %s(no evidence recorded)%s\n", gray, reset)
					continue
				}

				// Print up to 3 evidence items.
				limit := 3
				if len(entry.Evidence) < limit {
					limit = len(entry.Evidence)
				}
				for idx := 0; idx < limit; idx++ {
					ev := entry.Evidence[idx]
					file := ev.File
					if cwd != "" {
						if rel, err := filepath.Rel(cwd, ev.File); err == nil && !strings.HasPrefix(rel, "..") {
							file = rel
						}
					}
					loc := file
					if ev.Line > 0 {
						loc = fmt.Sprintf("%s:%d", file, ev.Line)
					}
					via := ev.Via
					if via == "" {
						via = ev.Context
					}
					confStr := ""
					if ev.Confidence > 0 {
						confStr = fmt.Sprintf(" conf:%.0f%%", ev.Confidence*100)
					}
					fmt.Fprintf(os.Stdout, "      %-55s  via:%-14s%s\n",
						loc, via+confStr, reset)
				}
				if len(entry.Evidence) > 3 {
					fmt.Fprintf(os.Stdout, "      %s... and %d more%s\n", gray, len(entry.Evidence)-3, reset)
				}
			}
		}
		fmt.Fprintln(os.Stdout)
	}
	return 0
}
