package scan

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// BenchmarkScanGoProject measures scan throughput on the minimal go-simple fixture.
// Run with: go test -bench=BenchmarkScanGoProject -benchtime=5s ./cmd/gorisk/scan/
func BenchmarkScanGoProject(b *testing.B) {
	fixtureDir, err := filepath.Abs(filepath.Join("testdata", "golden", "go-simple"))
	if err != nil {
		b.Fatal(err)
	}
	if _, err := os.Stat(fixtureDir); err != nil {
		b.Skip("go-simple fixture not found")
	}

	origDir, err := os.Getwd()
	if err != nil {
		b.Fatal(err)
	}
	if err := os.Chdir(fixtureDir); err != nil {
		b.Fatalf("chdir: %v", err)
	}
	b.Cleanup(func() { os.Chdir(origDir) }) //nolint:errcheck

	// Redirect stdout to discard output during benchmark.
	devNull, _ := os.Open(os.DevNull)
	defer devNull.Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		old := os.Stdout
		os.Stdout = devNull
		Run([]string{"--lang", "go"})
		os.Stdout = old
	}
}

// BenchmarkScanNodeProject measures scan throughput on the minimal node-simple fixture.
// Run with: go test -bench=BenchmarkScanNodeProject -benchtime=5s ./cmd/gorisk/scan/
func BenchmarkScanNodeProject(b *testing.B) {
	fixtureDir, err := filepath.Abs(filepath.Join("testdata", "golden", "node-simple"))
	if err != nil {
		b.Fatal(err)
	}
	if _, err := os.Stat(fixtureDir); err != nil {
		b.Skip("node-simple fixture not found")
	}

	origDir, err := os.Getwd()
	if err != nil {
		b.Fatal(err)
	}
	if err := os.Chdir(fixtureDir); err != nil {
		b.Fatalf("chdir: %v", err)
	}
	b.Cleanup(func() { os.Chdir(origDir) }) //nolint:errcheck

	devNull, _ := os.Open(os.DevNull)
	defer devNull.Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		old := os.Stdout
		os.Stdout = devNull
		Run([]string{"--lang", "node"})
		os.Stdout = old
	}
}

// perfGate runs scan once in fixtureDir (cd'd into it) and fails if elapsed
// exceeds limit. Skip with -short for CI jobs that don't need the gate.
func perfGate(t *testing.T, fixtureDir, lang string, limit time.Duration) {
	t.Helper()
	if testing.Short() {
		t.Skip("perf gate skipped in short mode")
	}
	if _, err := os.Stat(fixtureDir); err != nil {
		t.Skipf("fixture not found: %s", fixtureDir)
	}
	origDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(fixtureDir); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	t.Cleanup(func() { os.Chdir(origDir) }) //nolint:errcheck

	devNull, _ := os.Open(os.DevNull)
	defer devNull.Close()

	old := os.Stdout
	os.Stdout = devNull
	start := time.Now()
	Run([]string{"--lang", lang})
	elapsed := time.Since(start)
	os.Stdout = old

	if elapsed > limit {
		t.Errorf("scan took %v — exceeds %v budget (lang=%s, fixture=%s)",
			elapsed.Round(time.Millisecond), limit, lang, fixtureDir)
	}
}

// TestPerfGateGoProject asserts that a scan of the go-simple fixture completes
// within 10 s on any CI machine. Skipped with -short.
func TestPerfGateGoProject(t *testing.T) {
	dir, _ := filepath.Abs(filepath.Join("testdata", "golden", "go-simple"))
	perfGate(t, dir, "go", 10*time.Second)
}

// TestPerfGateNodeProject asserts that a scan of the node-simple fixture
// completes within 5 s. Skipped with -short.
func TestPerfGateNodeProject(t *testing.T) {
	dir, _ := filepath.Abs(filepath.Join("testdata", "golden", "node-simple"))
	perfGate(t, dir, "node", 5*time.Second)
}
