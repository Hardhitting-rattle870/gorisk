package upgrade

import (
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/1homsi/gorisk/internal/analyzer"
	"github.com/1homsi/gorisk/internal/engines/versiondiff"
	"github.com/1homsi/gorisk/internal/report"
)

func Run(args []string) int {
	fs := flag.NewFlagSet("upgrade", flag.ExitOnError)
	jsonOut := fs.Bool("json", false, "JSON output")
	lang := fs.String("lang", "auto", "language: auto|go|node")
	fs.Parse(args)

	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "usage: gorisk upgrade <module@version>")
		return 2
	}

	modulePath, version, ok := splitAt(fs.Arg(0))
	if !ok {
		fmt.Fprintln(os.Stderr, "specify version: module@version")
		return 2
	}

	dir, err := os.Getwd()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}

	features, err := analyzer.FeaturesFor(*lang, dir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "features:", err)
		return 2
	}
	r, err := features.Upgrade.Analyze(dir, modulePath, version)
	if err != nil {
		fmt.Fprintln(os.Stderr, "upgrade analysis:", err)
		return 2
	}

	// Compute transitive additions by comparing lockfile state.
	transitiveAdditions := computeTransitiveAdditions(dir, modulePath, version, *lang)

	if *jsonOut {
		if err := report.WriteUpgradeJSON(os.Stdout, r); err != nil {
			fmt.Fprintln(os.Stderr, "write output:", err)
			return 2
		}
		// Print transitive additions as supplementary JSON if present.
		if len(transitiveAdditions) > 0 {
			printTransitiveAdditionsJSON(transitiveAdditions)
		}
	} else {
		report.WriteUpgrade(os.Stdout, r)
		printTransitiveAdditionsText(transitiveAdditions)
	}

	if r.Risk == "HIGH" {
		return 1
	}
	return 0
}

// transitiveAddition represents a new transitive dependency introduced by an upgrade.
type transitiveAddition struct {
	Package string
	Version string
	NewCaps []string
}

// computeTransitiveAdditions detects new transitive deps introduced by the upgrade
// by comparing the current lockfile against the base (HEAD) lockfile via versiondiff.
// It uses the module name to scope results to deps added by that upgrade.
func computeTransitiveAdditions(dir, modulePath, _ string, lang string) []transitiveAddition {
	// Use versiondiff with HEAD as base to find new packages in the lockfile.
	dr, err := versiondiff.Compute(dir, "HEAD", lang)
	if err != nil {
		// Non-fatal: versiondiff may fail if not in a git repo or no lockfile.
		return nil
	}

	var additions []transitiveAddition
	seen := make(map[string]bool)

	for _, pd := range dr.NewPackages {
		// Exclude the module being upgraded itself; we want the transitive deps.
		pkgName := strings.SplitN(pd.Package, "@", 2)[0]
		if pkgName == modulePath {
			continue
		}
		if seen[pd.Package] {
			continue
		}
		seen[pd.Package] = true

		ver := ""
		if parts := strings.SplitN(pd.Package, "@", 2); len(parts) == 2 {
			ver = parts[1]
		}
		additions = append(additions, transitiveAddition{
			Package: pkgName,
			Version: ver,
			NewCaps: pd.NewCaps,
		})
	}

	sort.Slice(additions, func(i, j int) bool {
		return additions[i].Package < additions[j].Package
	})
	return additions
}

func printTransitiveAdditionsText(additions []transitiveAddition) {
	if len(additions) == 0 {
		return
	}

	const (
		bold  = "\033[1m"
		cyan  = "\033[36m"
		green = "\033[32m"
		reset = "\033[0m"
	)

	fmt.Fprintf(os.Stdout, "\n%s%s=== Transitive Additions ===%s\n", bold, cyan, reset)
	for _, a := range additions {
		capStr := ""
		if len(a.NewCaps) > 0 {
			capStr = fmt.Sprintf("   (new cap: %s)", strings.Join(a.NewCaps, ", "))
		}
		fmt.Fprintf(os.Stdout, "  %s+ %s@%s%s%s%s\n",
			green, a.Package, a.Version, reset, capStr, reset)
	}
}

func printTransitiveAdditionsJSON(additions []transitiveAddition) {
	// Print a simple JSON array to stdout appended after the upgrade JSON.
	// This is a supplementary output, so we prefix with a comment line.
	fmt.Fprintln(os.Stdout)
	fmt.Fprintln(os.Stdout, "// transitive_additions:")
	fmt.Fprintf(os.Stdout, "[")
	for i, a := range additions {
		caps := "[]"
		if len(a.NewCaps) > 0 {
			quoted := make([]string, len(a.NewCaps))
			for j, c := range a.NewCaps {
				quoted[j] = fmt.Sprintf("%q", c)
			}
			caps = "[" + strings.Join(quoted, ",") + "]"
		}
		comma := ","
		if i == len(additions)-1 {
			comma = ""
		}
		fmt.Fprintf(os.Stdout, "\n  {\"package\":%q,\"version\":%q,\"new_caps\":%s}%s",
			a.Package, a.Version, caps, comma)
	}
	fmt.Fprintln(os.Stdout, "\n]")
}

func splitAt(s string) (left, right string, ok bool) {
	at := strings.LastIndex(s, "@")
	if at == -1 {
		return "", "", false
	}
	return s[:at], s[at+1:], true
}
