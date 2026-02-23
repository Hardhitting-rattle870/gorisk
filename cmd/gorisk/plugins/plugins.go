// Package plugins implements the "gorisk plugins" subcommand, which lets users
// list, install (copy), and remove gorisk plugins.
package plugins

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/1homsi/gorisk/internal/plugin"
)

// Run is the entry point for "gorisk plugins [list|install|remove] [args...]".
func Run(args []string) int {
	if len(args) == 0 {
		return runList(nil)
	}

	sub := args[0]
	rest := args[1:]

	switch sub {
	case "list":
		return runList(rest)
	case "install":
		return runInstall(rest)
	case "remove":
		return runRemove(rest)
	default:
		fmt.Fprintf(os.Stderr, "unknown plugins subcommand: %q\n", sub)
		usage()
		return 2
	}
}

// ── list ─────────────────────────────────────────────────────────────────────

func runList(_ []string) int {
	dir := plugin.PluginDir()
	loaded, errs := plugin.LoadDir(dir)

	if len(errs) > 0 {
		for _, err := range errs {
			fmt.Fprintln(os.Stderr, "[WARN]", err)
		}
	}

	if len(loaded) == 0 {
		fmt.Println("No plugins installed.")
		fmt.Printf("Plugin directory: %s\n", dir)
		return 0
	}

	fmt.Printf("Installed plugins (%s):\n\n", dir)
	for _, lp := range loaded {
		name := filepath.Base(lp.Path)
		var kinds []string
		if lp.Detector != nil {
			kinds = append(kinds, "CapabilityDetector("+lp.Detector.Language()+")")
		}
		if lp.Scorer != nil {
			kinds = append(kinds, "RiskScorer("+lp.Scorer.Name()+")")
		}
		fmt.Printf("  %-30s  %s\n", name, strings.Join(kinds, ", "))
	}
	return 0
}

// ── install ───────────────────────────────────────────────────────────────────

func runInstall(args []string) int {
	fs := flag.NewFlagSet("plugins install", flag.ExitOnError)
	force := fs.Bool("force", false, "overwrite an existing plugin with the same name")
	fs.Parse(args) //nolint:errcheck

	if fs.NArg() == 0 {
		fmt.Fprintln(os.Stderr, "usage: gorisk plugins install [--force] <plugin.so>")
		return 2
	}

	dir := plugin.PluginDir()
	if err := os.MkdirAll(dir, 0o750); err != nil {
		fmt.Fprintln(os.Stderr, "create plugin dir:", err)
		return 2
	}

	src := fs.Arg(0)
	dst := filepath.Join(dir, filepath.Base(src))

	if !*force {
		if _, err := os.Stat(dst); err == nil {
			fmt.Fprintf(os.Stderr, "plugin %q already installed (use --force to overwrite)\n", filepath.Base(src))
			return 1
		}
	}

	if err := copyFile(src, dst); err != nil {
		fmt.Fprintln(os.Stderr, "install plugin:", err)
		return 2
	}

	fmt.Printf("Installed %s → %s\n", filepath.Base(src), dst)
	return 0
}

// ── remove ────────────────────────────────────────────────────────────────────

func runRemove(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: gorisk plugins remove <plugin-name>")
		return 2
	}

	dir := plugin.PluginDir()
	name := args[0]
	if !strings.HasSuffix(name, ".so") {
		name += ".so"
	}
	path := filepath.Join(dir, filepath.Base(name))

	if err := os.Remove(path); err != nil {
		if os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "plugin %q not found\n", name)
			return 1
		}
		fmt.Fprintln(os.Stderr, "remove plugin:", err)
		return 2
	}

	fmt.Printf("Removed %s\n", name)
	return 0
}

// ── helpers ───────────────────────────────────────────────────────────────────

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer out.Close()

	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	return out.Close()
}

func usage() {
	fmt.Fprintln(os.Stderr, `gorisk plugins — manage gorisk plugins

Usage:
  gorisk plugins list
  gorisk plugins install [--force] <plugin.so>
  gorisk plugins remove <plugin-name>`)
}
