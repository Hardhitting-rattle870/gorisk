// Package gorisk exposes gorisk's risk analysis capabilities as a stable
// public API. Types in this package have semver stability guarantees;
// internal packages may change freely.
package gorisk

// RiskLevel represents the severity of a risk finding.
type RiskLevel string

const (
	RiskLow    RiskLevel = "LOW"
	RiskMedium RiskLevel = "MEDIUM"
	RiskHigh   RiskLevel = "HIGH"
)

// Finding holds the capability risk result for a single package.
type Finding struct {
	Package      string    `json:"package"`
	Module       string    `json:"module,omitempty"`
	Capabilities []string  `json:"capabilities,omitempty"`
	Risk         RiskLevel `json:"risk"`
	Score        float64   `json:"score"`
}

// TaintFinding records a source→sink data-flow risk path.
type TaintFinding struct {
	Package    string    `json:"package"`
	Module     string    `json:"module,omitempty"`
	Source     string    `json:"source"`
	Sink       string    `json:"sink"`
	Risk       RiskLevel `json:"risk"`
	Note       string    `json:"note,omitempty"`
	Confidence float64   `json:"confidence"`
}

// ScanResult is the top-level output of a Scanner.Scan() call.
type ScanResult struct {
	SchemaVersion string         `json:"schema_version"`
	Passed        bool           `json:"passed"`
	FailReason    string         `json:"fail_reason,omitempty"`
	Findings      []Finding      `json:"findings,omitempty"`
	TaintFlows    []TaintFinding `json:"taint_flows,omitempty"`
}
