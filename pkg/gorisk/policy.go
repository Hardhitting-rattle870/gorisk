package gorisk

import (
	"encoding/json"
	"os"
)

// PolicyException allows a specific package+capability combination to be
// excluded from policy enforcement.
type PolicyException struct {
	Package      string   `json:"package"`
	Capabilities []string `json:"capabilities,omitempty"`
	Taint        []string `json:"taint,omitempty"`
	Expires      string   `json:"expires,omitempty"`
}

// Policy configures scan behaviour and enforcement rules.
// The zero value is valid and uses safe defaults (fail_on: "high").
type Policy struct {
	Version             int               `json:"version,omitempty"`
	FailOn              string            `json:"fail_on,omitempty"`
	DenyCapabilities    []string          `json:"deny_capabilities,omitempty"`
	AllowExceptions     []PolicyException `json:"allow_exceptions,omitempty"`
	ExcludePackages     []string          `json:"exclude_packages,omitempty"`
	ConfidenceThreshold float64           `json:"confidence_threshold,omitempty"`
	MaxDepDepth         int               `json:"max_dep_depth,omitempty"`
}

// DefaultPolicy returns a Policy with recommended defaults.
func DefaultPolicy() Policy {
	return Policy{
		Version: 1,
		FailOn:  "high",
	}
}

// LoadPolicy reads and parses a policy JSON file.
// Returns DefaultPolicy() and a non-nil error if the file cannot be read or
// parsed.
func LoadPolicy(path string) (Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return DefaultPolicy(), err
	}
	var p Policy
	if err := json.Unmarshal(data, &p); err != nil {
		return DefaultPolicy(), err
	}
	return p, nil
}
