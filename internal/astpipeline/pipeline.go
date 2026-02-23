package astpipeline

import (
	"fmt"

	goadapter "github.com/1homsi/gorisk/internal/adapters/go"
	nodeadapter "github.com/1homsi/gorisk/internal/adapters/node"
	"github.com/1homsi/gorisk/internal/graph"
	"github.com/1homsi/gorisk/internal/interproc"
	"github.com/1homsi/gorisk/internal/ir"
)

// Result is a command-friendly wrapper around interprocedural analysis outputs.
type Result struct {
	Bundle        interproc.ResultBundle
	UsedInterproc bool
	Reason        string
}

// Analyze tries to run interprocedural AST analysis for the given language.
// It always returns a Result; callers should fall back when UsedInterproc is false.
func Analyze(dir, lang string, g *graph.DependencyGraph) Result {
	irGraph, err := buildIR(dir, lang, g)
	if err != nil {
		return Result{UsedInterproc: false, Reason: err.Error()}
	}
	if len(irGraph.Functions) == 0 {
		return Result{UsedInterproc: false, Reason: "no function-level IR available"}
	}
	bundle, err := interproc.RunBundle(irGraph, interproc.DefaultOptions())
	if err != nil {
		return Result{UsedInterproc: false, Reason: err.Error()}
	}
	return Result{Bundle: bundle, UsedInterproc: true, Reason: "interproc enabled"}
}

func buildIR(dir, lang string, g *graph.DependencyGraph) (ir.IRGraph, error) {
	switch lang {
	case "go":
		return goadapter.BuildIRGraph(dir, g)
	case "node":
		return nodeadapter.BuildIRGraph(g), nil
	default:
		return ir.IRGraph{}, fmt.Errorf("interproc not available for lang %q", lang)
	}
}
