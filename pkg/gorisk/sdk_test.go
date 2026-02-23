package gorisk_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/1homsi/gorisk/pkg/gorisk"
)

func TestDefaultPolicy(t *testing.T) {
	p := gorisk.DefaultPolicy()
	if p.FailOn != "high" {
		t.Errorf("DefaultPolicy().FailOn = %q, want %q", p.FailOn, "high")
	}
	if p.Version != 1 {
		t.Errorf("DefaultPolicy().Version = %d, want 1", p.Version)
	}
}

func TestLoadPolicyMissing(t *testing.T) {
	_, err := gorisk.LoadPolicy("/nonexistent/policy.json")
	if err == nil {
		t.Error("expected error for missing policy file, got nil")
	}
}

func TestLoadPolicyValid(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.json")
	content := `{"version":1,"fail_on":"medium","deny_capabilities":["exec"]}`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	p, err := gorisk.LoadPolicy(path)
	if err != nil {
		t.Fatalf("LoadPolicy: %v", err)
	}
	if p.FailOn != "medium" {
		t.Errorf("FailOn = %q, want %q", p.FailOn, "medium")
	}
	if len(p.DenyCapabilities) != 1 || p.DenyCapabilities[0] != "exec" {
		t.Errorf("DenyCapabilities = %v, want [exec]", p.DenyCapabilities)
	}
}

func TestNewScanner(t *testing.T) {
	dir := t.TempDir()
	s := gorisk.NewScanner(gorisk.ScanOptions{
		Dir:  dir,
		Lang: "go",
	})
	if s == nil {
		t.Fatal("NewScanner returned nil")
	}
}

func TestNewScannerDefaults(t *testing.T) {
	// Empty opts — should fill in defaults without panicking.
	s := gorisk.NewScanner(gorisk.ScanOptions{})
	if s == nil {
		t.Fatal("NewScanner(empty) returned nil")
	}
}

func TestScannerGoSimple(t *testing.T) {
	dir := t.TempDir()

	// Write a minimal Go module.
	goMod := "module example.com/simple\ngo 1.21\n"
	mainGo := `package main

import "fmt"

func main() { fmt.Println("hello") }
`
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(goMod), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(mainGo), 0o600); err != nil {
		t.Fatal(err)
	}

	s := gorisk.NewScanner(gorisk.ScanOptions{Dir: dir, Lang: "go"})
	result, err := s.Scan()
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if result == nil {
		t.Fatal("Scan returned nil result")
	}
	if result.SchemaVersion != "v1" {
		t.Errorf("SchemaVersion = %q, want %q", result.SchemaVersion, "v1")
	}
}

func TestRiskLevelConstants(t *testing.T) {
	if gorisk.RiskLow != "LOW" {
		t.Error("RiskLow != LOW")
	}
	if gorisk.RiskMedium != "MEDIUM" {
		t.Error("RiskMedium != MEDIUM")
	}
	if gorisk.RiskHigh != "HIGH" {
		t.Error("RiskHigh != HIGH")
	}
}
