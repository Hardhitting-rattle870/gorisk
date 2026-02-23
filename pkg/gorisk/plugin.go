package gorisk

// CapabilityDetector is the interface that gorisk plugin authors implement to
// extend capability detection to new languages or frameworks.
//
// The gorisk plugin system uses Go's plugin package (go build -buildmode=plugin).
// Plugins must export a symbol named "CapabilityDetector" that implements this
// interface.
type CapabilityDetector interface {
	// Language returns the identifier for which this detector applies, e.g. "python".
	Language() string
	// DetectFile scans a single source file and returns a map of capability
	// names (e.g. "exec", "network") to confidence values in [0,1].
	DetectFile(path string) (map[string]float64, error)
}

// RiskScorer allows plugins to contribute additional scoring signals beyond
// gorisk's built-in multi-engine additive scorer.
//
// Plugins must export a symbol named "RiskScorer" that implements this interface.
type RiskScorer interface {
	// Name returns a short identifier for this scorer, used in diagnostics.
	Name() string
	// Score returns an additional risk score contribution (0–20) for the
	// given package. Contributions are capped and summed into the final score.
	Score(pkg string, caps []string) float64
}
