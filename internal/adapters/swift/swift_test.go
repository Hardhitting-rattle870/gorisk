package swift

import (
	"os"
	"path/filepath"
	"testing"
)

// ---------------------------------------------------------------------------
// Lockfile parser tests
// ---------------------------------------------------------------------------

func TestLoadPackageResolved(t *testing.T) {
	dir := t.TempDir()

	resolved := `{
  "pins": [
    {
      "identity": "alamofire",
      "kind": "remoteSourceControl",
      "location": "https://github.com/Alamofire/Alamofire.git",
      "state": {
        "revision": "bf5b8bc9e5a5bb1ff24f5a7dab58c60cf36a1c1a",
        "version": "5.9.1"
      }
    },
    {
      "identity": "cryptokit",
      "kind": "remoteSourceControl",
      "location": "https://github.com/apple/swift-crypto.git",
      "state": {
        "revision": "abc123",
        "version": "3.1.0"
      }
    }
  ],
  "version": 2
}`
	if err := os.WriteFile(filepath.Join(dir, "Package.resolved"), []byte(resolved), 0o600); err != nil {
		t.Fatal(err)
	}

	pkgs, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	byName := make(map[string]SwiftPackage)
	for _, p := range pkgs {
		byName[p.Name] = p
	}

	if _, ok := byName["Alamofire"]; !ok {
		t.Error("expected 'Alamofire' in packages")
	}
	if byName["Alamofire"].Version != "5.9.1" {
		t.Errorf("Alamofire version: got %q, want %q", byName["Alamofire"].Version, "5.9.1")
	}
	if !byName["Alamofire"].Direct {
		t.Error("Alamofire should be a direct dep (SPM lockfile marks all as direct)")
	}
	if _, ok := byName["Cryptokit"]; !ok {
		t.Error("expected 'Cryptokit' in packages")
	}
}

func TestLoadPackageResolvedV3(t *testing.T) {
	dir := t.TempDir()

	resolved := `{
  "pins": [
    {
      "identity": "vapor",
      "kind": "remoteSourceControl",
      "location": "https://github.com/vapor/vapor.git",
      "state": {
        "revision": "deadbeef",
        "version": "4.89.0"
      }
    }
  ],
  "version": 3
}`
	if err := os.WriteFile(filepath.Join(dir, "Package.resolved"), []byte(resolved), 0o600); err != nil {
		t.Fatal(err)
	}

	pkgs, err := Load(dir)
	if err != nil {
		t.Fatalf("Load v3: %v", err)
	}
	if len(pkgs) != 1 {
		t.Fatalf("expected 1 package, got %d", len(pkgs))
	}
	if pkgs[0].Name != "Vapor" {
		t.Errorf("name: got %q, want %q", pkgs[0].Name, "Vapor")
	}
	if pkgs[0].Version != "4.89.0" {
		t.Errorf("version: got %q, want %q", pkgs[0].Version, "4.89.0")
	}
}

func TestLoadPackageResolvedV1(t *testing.T) {
	dir := t.TempDir()

	resolved := `{
  "object": {
    "pins": [
      {
        "package": "Alamofire",
        "repositoryURL": "https://github.com/Alamofire/Alamofire.git",
        "state": {
          "branch": null,
          "revision": "abc",
          "version": "5.7.1"
        }
      },
      {
        "package": "SwiftyJSON",
        "repositoryURL": "https://github.com/SwiftyJSON/SwiftyJSON.git",
        "state": {
          "branch": null,
          "revision": "def",
          "version": "5.0.1"
        }
      }
    ]
  },
  "version": 1
}`
	if err := os.WriteFile(filepath.Join(dir, "Package.resolved"), []byte(resolved), 0o600); err != nil {
		t.Fatal(err)
	}

	pkgs, err := Load(dir)
	if err != nil {
		t.Fatalf("Load v1: %v", err)
	}

	byName := make(map[string]SwiftPackage)
	for _, p := range pkgs {
		byName[p.Name] = p
	}

	if _, ok := byName["Alamofire"]; !ok {
		t.Error("expected 'Alamofire' in v1 packages")
	}
	if byName["Alamofire"].Version != "5.7.1" {
		t.Errorf("Alamofire v1 version: got %q, want %q", byName["Alamofire"].Version, "5.7.1")
	}
	if _, ok := byName["SwiftyJSON"]; !ok {
		t.Error("expected 'SwiftyJSON' in v1 packages")
	}
}

func TestLoadPackageSwift(t *testing.T) {
	dir := t.TempDir()

	content := `// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "MyApp",
    dependencies: [
        .package(url: "https://github.com/Alamofire/Alamofire.git", from: "5.9.0"),
        .package(url: "https://github.com/vapor/vapor.git", from: "4.0.0"),
        .package(name: "CryptoKit", url: "https://github.com/apple/swift-crypto.git", from: "3.0.0"),
    ]
)
`
	if err := os.WriteFile(filepath.Join(dir, "Package.swift"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	pkgs, err := Load(dir)
	if err != nil {
		t.Fatalf("Load Package.swift: %v", err)
	}
	if len(pkgs) == 0 {
		t.Fatal("expected at least one package from Package.swift")
	}

	byName := make(map[string]SwiftPackage)
	for _, p := range pkgs {
		byName[p.Name] = p
	}

	// CryptoKit has an explicit name: argument — should be found.
	if _, ok := byName["CryptoKit"]; !ok {
		t.Error("expected 'CryptoKit' from name: argument")
	}
	// Alamofire from URL basename.
	if _, ok := byName["Alamofire"]; !ok {
		t.Error("expected 'Alamofire' from URL basename")
	}
}

func TestLoadEmptyDir(t *testing.T) {
	dir := t.TempDir()
	_, err := Load(dir)
	if err == nil {
		t.Error("expected error for directory with no Swift lockfiles")
	}
}

func TestLoadEmptyPackageResolved(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "Package.resolved"), []byte{}, 0o600); err != nil {
		t.Fatal(err)
	}
	pkgs, err := loadPackageResolved(dir)
	if err != nil {
		t.Fatalf("unexpected error for empty Package.resolved: %v", err)
	}
	if len(pkgs) != 0 {
		t.Errorf("expected 0 packages for empty file, got %d", len(pkgs))
	}
}

// ---------------------------------------------------------------------------
// Capability detection tests
// ---------------------------------------------------------------------------

func TestDetectCapabilities(t *testing.T) {
	dir := t.TempDir()
	src := `import Foundation
import CryptoKit

let session = URLSession.shared
let url = URL(string: "https://example.com")!
let request = URLRequest(url: url)

let hash = SHA256.hash(data: Data())

let fm = FileManager.default
let path = fm.currentDirectoryPath
`
	if err := os.WriteFile(filepath.Join(dir, "main.swift"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}

	caps := Detect(dir)

	wantCaps := []string{"network", "crypto", "fs:read", "fs:write"}
	for _, want := range wantCaps {
		if !caps.Has(want) {
			t.Errorf("expected capability %q to be detected", want)
		}
	}
}

func TestDetectNoCapabilities(t *testing.T) {
	dir := t.TempDir()
	src := `func add(_ a: Int, _ b: Int) -> Int {
    return a + b
}

func greet(_ name: String) -> String {
    return "Hello, \(name)"
}
`
	if err := os.WriteFile(filepath.Join(dir, "utils.swift"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}

	caps := Detect(dir)
	if !caps.IsEmpty() {
		t.Errorf("expected no capabilities for benign code, got: %v", caps.List())
	}
}

// ---------------------------------------------------------------------------
// Adapter integration tests
// ---------------------------------------------------------------------------

func TestAdapterName(t *testing.T) {
	a := &Adapter{}
	if a.Name() != "swift" {
		t.Errorf("Name(): got %q, want %q", a.Name(), "swift")
	}
}

func TestAdapterLoad(t *testing.T) {
	dir := t.TempDir()

	resolved := `{
  "pins": [
    {
      "identity": "alamofire",
      "kind": "remoteSourceControl",
      "location": "https://github.com/Alamofire/Alamofire.git",
      "state": {
        "revision": "abc",
        "version": "5.9.1"
      }
    },
    {
      "identity": "vapor",
      "kind": "remoteSourceControl",
      "location": "https://github.com/vapor/vapor.git",
      "state": {
        "revision": "def",
        "version": "4.89.0"
      }
    }
  ],
  "version": 2
}`
	if err := os.WriteFile(filepath.Join(dir, "Package.resolved"), []byte(resolved), 0o600); err != nil {
		t.Fatal(err)
	}

	a := &Adapter{}
	g, err := a.Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if g == nil {
		t.Fatal("Load returned nil graph")
	}

	// Should have root module + at least the two deps.
	if len(g.Modules) < 3 {
		t.Errorf("expected at least 3 modules (root + 2 deps), got %d", len(g.Modules))
	}

	if _, ok := g.Packages["Alamofire"]; !ok {
		t.Error("expected 'Alamofire' package in graph")
	}
	if _, ok := g.Packages["Vapor"]; !ok {
		t.Error("expected 'Vapor' package in graph")
	}

	// Alamofire should have network capability from import map.
	alamoPkg := g.Packages["Alamofire"]
	if !alamoPkg.Capabilities.Has("network") {
		t.Error("expected Alamofire to have 'network' capability")
	}
}

// ---------------------------------------------------------------------------
// Fuzz test
// ---------------------------------------------------------------------------

func FuzzParsePackageResolved(f *testing.F) {
	f.Add([]byte(`{"pins":[{"identity":"alamofire","kind":"remoteSourceControl","location":"https://github.com/Alamofire/Alamofire.git","state":{"revision":"abc","version":"5.9.1"}}],"version":2}`))
	f.Add([]byte(`{"object":{"pins":[{"package":"Alamofire","repositoryURL":"https://github.com/Alamofire/Alamofire.git","state":{"version":"5.7.1"}}]},"version":1}`))
	f.Add([]byte(""))
	f.Add([]byte("{}"))
	f.Add([]byte("not json"))

	f.Fuzz(func(t *testing.T, data []byte) {
		defer func() { recover() }() //nolint:errcheck

		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "Package.resolved"), data, 0o600); err != nil {
			return
		}
		loadPackageResolved(dir) //nolint:errcheck
	})
}
