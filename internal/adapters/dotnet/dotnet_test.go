package dotnet

import (
	"os"
	"path/filepath"
	"testing"
)

// ---------------------------------------------------------------------------
// Lockfile parser tests
// ---------------------------------------------------------------------------

func TestLoadPackagesLockJSON(t *testing.T) {
	dir := t.TempDir()

	lockContent := `{
  "version": 1,
  "dependencies": {
    "net8.0": {
      "Newtonsoft.Json": {
        "type": "Direct",
        "requested": "[13.0.1, )",
        "resolved": "13.0.3",
        "contentHash": "abc123",
        "dependencies": {
          "Microsoft.CSharp": "4.7.0"
        }
      },
      "Microsoft.CSharp": {
        "type": "Transitive",
        "resolved": "4.7.0",
        "contentHash": "def456"
      },
      "RestSharp": {
        "type": "Direct",
        "resolved": "110.2.0",
        "contentHash": "ghi789"
      }
    }
  }
}`
	if err := os.WriteFile(filepath.Join(dir, "packages.lock.json"), []byte(lockContent), 0o600); err != nil {
		t.Fatal(err)
	}

	pkgs, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	byName := make(map[string]DotnetPackage)
	for _, p := range pkgs {
		byName[p.Name] = p
	}

	if _, ok := byName["Newtonsoft.Json"]; !ok {
		t.Error("expected 'Newtonsoft.Json' in packages")
	}
	if byName["Newtonsoft.Json"].Version != "13.0.3" {
		t.Errorf("Newtonsoft.Json version: got %q, want %q", byName["Newtonsoft.Json"].Version, "13.0.3")
	}
	if !byName["Newtonsoft.Json"].Direct {
		t.Error("Newtonsoft.Json should be a direct dep")
	}
	if _, ok := byName["Microsoft.CSharp"]; !ok {
		t.Error("expected 'Microsoft.CSharp' in packages")
	}
	if byName["Microsoft.CSharp"].Direct {
		t.Error("Microsoft.CSharp should not be a direct dep")
	}
	if _, ok := byName["RestSharp"]; !ok {
		t.Error("expected 'RestSharp' in packages")
	}
	if !byName["RestSharp"].Direct {
		t.Error("RestSharp should be a direct dep")
	}

	// Newtonsoft.Json should have Microsoft.CSharp as a dependency.
	found := false
	for _, dep := range byName["Newtonsoft.Json"].Dependencies {
		if dep == "Microsoft.CSharp" {
			found = true
		}
	}
	if !found {
		t.Error("Newtonsoft.Json should depend on Microsoft.CSharp")
	}
}

func TestLoadPackagesLockJSONMultiFramework(t *testing.T) {
	dir := t.TempDir()

	// Package appears in two target frameworks — should be merged (Direct wins).
	lockContent := `{
  "version": 1,
  "dependencies": {
    "net6.0": {
      "Serilog": {
        "type": "Transitive",
        "resolved": "3.0.0",
        "contentHash": "aaa"
      }
    },
    "net8.0": {
      "Serilog": {
        "type": "Direct",
        "resolved": "3.0.0",
        "contentHash": "bbb"
      }
    }
  }
}`
	if err := os.WriteFile(filepath.Join(dir, "packages.lock.json"), []byte(lockContent), 0o600); err != nil {
		t.Fatal(err)
	}

	pkgs, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	byName := make(map[string]DotnetPackage)
	for _, p := range pkgs {
		byName[p.Name] = p
	}

	if _, ok := byName["Serilog"]; !ok {
		t.Error("expected 'Serilog' in packages")
	}
	if !byName["Serilog"].Direct {
		t.Error("Serilog should be Direct (upgraded from multi-framework)")
	}
}

func TestLoadCsproj(t *testing.T) {
	dir := t.TempDir()

	csprojContent := `<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net8.0</TargetFramework>
  </PropertyGroup>
  <ItemGroup>
    <PackageReference Include="Newtonsoft.Json" Version="13.0.3" />
    <PackageReference Include="Microsoft.Extensions.Logging" Version="8.0.0" />
    <PackageReference Include="RestSharp" Version="110.2.0" />
  </ItemGroup>
</Project>`
	if err := os.WriteFile(filepath.Join(dir, "MyApp.csproj"), []byte(csprojContent), 0o600); err != nil {
		t.Fatal(err)
	}

	pkgs, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	byName := make(map[string]DotnetPackage)
	for _, p := range pkgs {
		byName[p.Name] = p
	}

	if _, ok := byName["Newtonsoft.Json"]; !ok {
		t.Error("expected 'Newtonsoft.Json' in packages")
	}
	if byName["Newtonsoft.Json"].Version != "13.0.3" {
		t.Errorf("Newtonsoft.Json version: got %q, want %q", byName["Newtonsoft.Json"].Version, "13.0.3")
	}
	if !byName["Newtonsoft.Json"].Direct {
		t.Error("Newtonsoft.Json should be a direct dep")
	}
	if _, ok := byName["Microsoft.Extensions.Logging"]; !ok {
		t.Error("expected 'Microsoft.Extensions.Logging' in packages")
	}
	if _, ok := byName["RestSharp"]; !ok {
		t.Error("expected 'RestSharp' in packages")
	}
}

func TestLoadEmptyDir(t *testing.T) {
	dir := t.TempDir()
	_, err := Load(dir)
	if err == nil {
		t.Error("expected error for directory with no .NET lockfiles")
	}
}

func TestLoadPackagesLockJSONEmpty(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "packages.lock.json"), []byte{}, 0o600); err != nil {
		t.Fatal(err)
	}
	pkgs, err := loadPackagesLockJSON(dir)
	if err != nil {
		t.Fatalf("loadPackagesLockJSON() unexpected error for empty file: %v", err)
	}
	if len(pkgs) != 0 {
		t.Errorf("expected 0 packages for empty packages.lock.json, got %d", len(pkgs))
	}
}

func TestLoadCsprojEmpty(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "Empty.csproj")
	if err := os.WriteFile(path, []byte{}, 0o600); err != nil {
		t.Fatal(err)
	}
	pkgs, err := loadCsproj(path)
	if err != nil {
		t.Fatalf("loadCsproj() unexpected error for empty file: %v", err)
	}
	if len(pkgs) != 0 {
		t.Errorf("expected 0 packages for empty csproj, got %d", len(pkgs))
	}
}

// ---------------------------------------------------------------------------
// Capability detection tests
// ---------------------------------------------------------------------------

func TestDetectCapabilities(t *testing.T) {
	dir := t.TempDir()
	src := `using System.Net.Http;
using System.Diagnostics;

namespace MyApp
{
    class Program
    {
        static void Main(string[] args)
        {
            Process.Start("ls");
            var client = new HttpClient();
            var response = client.GetAsync("https://example.com").Result;
        }
    }
}
`
	if err := os.WriteFile(filepath.Join(dir, "Program.cs"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}

	caps := Detect(dir)

	wantCaps := []string{"network", "exec"}
	for _, want := range wantCaps {
		if !caps.Has(want) {
			t.Errorf("expected capability %q to be detected", want)
		}
	}
}

func TestDetectNoCapabilities(t *testing.T) {
	dir := t.TempDir()
	src := `namespace MyApp
{
    public class Calculator
    {
        public int Add(int a, int b) => a + b;
        public int Subtract(int a, int b) => a - b;
        public string Greet(string name) => $"Hello, {name}!";
    }
}
`
	if err := os.WriteFile(filepath.Join(dir, "Calculator.cs"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}

	caps := Detect(dir)
	if !caps.IsEmpty() {
		t.Errorf("expected no capabilities for benign code, got: %v", caps.List())
	}
}

func TestDetectCryptoCapabilities(t *testing.T) {
	dir := t.TempDir()
	src := `using System.Security.Cryptography;

namespace MyApp
{
    class Hasher
    {
        public byte[] Hash(byte[] data)
        {
            using var sha = SHA256.Create();
            return sha.ComputeHash(data);
        }
    }
}
`
	if err := os.WriteFile(filepath.Join(dir, "Hasher.cs"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}

	caps := Detect(dir)
	if !caps.Has("crypto") {
		t.Error("expected 'crypto' capability from System.Security.Cryptography using + SHA256.Create(")
	}
}

func TestDetectFileSystemCapabilities(t *testing.T) {
	dir := t.TempDir()
	src := `using System.IO;

namespace MyApp
{
    class FileHelper
    {
        public string Read(string path) => File.ReadAllText(path);
        public void Write(string path, string data) { File.WriteAllText(path, data); }
    }
}
`
	if err := os.WriteFile(filepath.Join(dir, "FileHelper.cs"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}

	caps := Detect(dir)
	if !caps.Has("fs:read") {
		t.Error("expected 'fs:read' capability")
	}
	if !caps.Has("fs:write") {
		t.Error("expected 'fs:write' capability")
	}
}

// ---------------------------------------------------------------------------
// Adapter tests
// ---------------------------------------------------------------------------

func TestAdapterName(t *testing.T) {
	a := &Adapter{}
	if a.Name() != "dotnet" {
		t.Errorf("Name(): got %q, want %q", a.Name(), "dotnet")
	}
}

func TestAdapterLoad(t *testing.T) {
	dir := t.TempDir()

	lockContent := `{
  "version": 1,
  "dependencies": {
    "net8.0": {
      "Newtonsoft.Json": {
        "type": "Direct",
        "resolved": "13.0.3",
        "contentHash": "abc"
      },
      "RestSharp": {
        "type": "Direct",
        "resolved": "110.2.0",
        "contentHash": "def"
      }
    }
  }
}`
	if err := os.WriteFile(filepath.Join(dir, "packages.lock.json"), []byte(lockContent), 0o600); err != nil {
		t.Fatal(err)
	}

	csSource := `using System.Net.Http;
using System.Diagnostics;

namespace MyApp
{
    class Program
    {
        static void Main() { Process.Start("cmd"); }
    }
}
`
	if err := os.WriteFile(filepath.Join(dir, "Program.cs"), []byte(csSource), 0o600); err != nil {
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

	// Should have root module + at least the two direct deps.
	if len(g.Modules) < 3 {
		t.Errorf("expected at least 3 modules (root + 2 deps), got %d", len(g.Modules))
	}

	if _, ok := g.Packages["Newtonsoft.Json"]; !ok {
		t.Error("expected 'Newtonsoft.Json' package in graph")
	}
	if _, ok := g.Packages["RestSharp"]; !ok {
		t.Error("expected 'RestSharp' package in graph")
	}

	// Root package should have exec+network from .cs source file.
	rootName := filepath.Base(dir)
	rootPkg, ok := g.Packages[rootName]
	if !ok {
		t.Fatalf("root package %q not found in graph", rootName)
	}
	if !rootPkg.Capabilities.Has("exec") {
		t.Error("root package should have 'exec' capability from Process.Start(")
	}
	if !rootPkg.Capabilities.Has("network") {
		t.Error("root package should have 'network' capability from System.Net.Http using")
	}
}

func TestAdapterLoadCsproj(t *testing.T) {
	dir := t.TempDir()

	csprojContent := `<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference Include="System.Net.Http" Version="4.3.4" />
  </ItemGroup>
</Project>`
	if err := os.WriteFile(filepath.Join(dir, "App.csproj"), []byte(csprojContent), 0o600); err != nil {
		t.Fatal(err)
	}

	a := &Adapter{}
	g, err := a.Load(dir)
	if err != nil {
		t.Fatalf("Load (csproj): %v", err)
	}
	if g == nil {
		t.Fatal("Load returned nil graph")
	}

	// RestSharp is network capable from import rules.
	netPkg, ok := g.Packages["System.Net.Http"]
	if !ok {
		t.Fatal("expected 'System.Net.Http' in graph")
	}
	if !netPkg.Capabilities.Has("network") {
		t.Error("System.Net.Http should have 'network' capability from import rule")
	}
}

// ---------------------------------------------------------------------------
// Fuzz test
// ---------------------------------------------------------------------------

func FuzzParsePackagesLock(f *testing.F) {
	f.Add([]byte(`{"version":1,"dependencies":{"net8.0":{"Foo":{"type":"Direct","resolved":"1.0.0","contentHash":"abc"}}}}`))
	f.Add([]byte(""))
	f.Add([]byte("{}"))
	f.Add([]byte(`{"version":1,"dependencies":{}}`))
	f.Add([]byte("not json at all"))

	f.Fuzz(func(t *testing.T, data []byte) {
		defer func() { recover() }() //nolint:errcheck

		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "packages.lock.json"), data, 0o600); err != nil {
			return
		}
		loadPackagesLockJSON(dir) //nolint:errcheck
	})
}
