package elixir

import (
	"os"
	"path/filepath"
	"testing"
)

// ---------------------------------------------------------------------------
// Lockfile parser tests
// ---------------------------------------------------------------------------

func TestLoadMixLock(t *testing.T) {
	dir := t.TempDir()

	// Write mix.exs so direct deps can be detected.
	mixExs := `defmodule MyApp.MixProject do
  use Mix.Project

  defp deps do
    [
      {:bcrypt_elixir, "~> 3.0"},
      {:comeonin, "~> 5.3"},
    ]
  end
end
`
	mixLock := `%{
  "bcrypt_elixir": {:hex, :bcrypt_elixir, "3.0.1", "abc123", [:mix], [{:comeonin, "~> 5.3", [hex: :comeonin, repo: "hexpm", optional: false]}, {:elixir_make, "~> 0.6", [hex: :elixir_make, repo: "hexpm", optional: false]}], "hexpm", "def456"},
  "certifi": {:hex, :certifi, "2.12.0", "aaa111", [:rebar3], [], "hexpm", "bbb222"},
  "comeonin": {:hex, :comeonin, "5.4.0", "ccc333", [:mix], [], "hexpm", "ddd444"},
}
`
	if err := os.WriteFile(filepath.Join(dir, "mix.exs"), []byte(mixExs), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "mix.lock"), []byte(mixLock), 0o600); err != nil {
		t.Fatal(err)
	}

	pkgs, err := loadMixLock(dir)
	if err != nil {
		t.Fatalf("loadMixLock: %v", err)
	}

	byName := make(map[string]ElixirPackage)
	for _, p := range pkgs {
		byName[p.Name] = p
	}

	if _, ok := byName["bcrypt_elixir"]; !ok {
		t.Error("expected 'bcrypt_elixir' in packages")
	}
	if byName["bcrypt_elixir"].Version != "3.0.1" {
		t.Errorf("bcrypt_elixir version: got %q, want %q", byName["bcrypt_elixir"].Version, "3.0.1")
	}
	if !byName["bcrypt_elixir"].Direct {
		t.Error("bcrypt_elixir should be a direct dep (listed in mix.exs)")
	}
	if _, ok := byName["certifi"]; !ok {
		t.Error("expected 'certifi' in packages")
	}
	if byName["certifi"].Version != "2.12.0" {
		t.Errorf("certifi version: got %q, want %q", byName["certifi"].Version, "2.12.0")
	}
	if byName["certifi"].Direct {
		t.Error("certifi should not be a direct dep")
	}
	if _, ok := byName["comeonin"]; !ok {
		t.Error("expected 'comeonin' in packages")
	}
	if !byName["comeonin"].Direct {
		t.Error("comeonin should be a direct dep (listed in mix.exs)")
	}

	// bcrypt_elixir should depend on comeonin and elixir_make.
	found := false
	for _, dep := range byName["bcrypt_elixir"].Dependencies {
		if dep == "comeonin" {
			found = true
		}
	}
	if !found {
		t.Error("bcrypt_elixir should depend on comeonin")
	}
}

func TestLoadMixExs(t *testing.T) {
	dir := t.TempDir()
	content := `defmodule MyApp.MixProject do
  use Mix.Project

  def project do
    [app: :my_app, version: "0.1.0"]
  end

  defp deps do
    [
      {:httpoison, "~> 1.8"},
      {:jason, ">= 1.0.0"},
      {:ecto, "~> 3.10", only: :test},
    ]
  end
end
`
	if err := os.WriteFile(filepath.Join(dir, "mix.exs"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	pkgs, err := loadMixExs(dir)
	if err != nil {
		t.Fatalf("loadMixExs: %v", err)
	}

	byName := make(map[string]ElixirPackage)
	for _, p := range pkgs {
		byName[p.Name] = p
	}

	if _, ok := byName["httpoison"]; !ok {
		t.Error("expected 'httpoison' in packages")
	}
	if _, ok := byName["jason"]; !ok {
		t.Error("expected 'jason' in packages")
	}
	if _, ok := byName["ecto"]; !ok {
		t.Error("expected 'ecto' in packages")
	}
	for _, name := range []string{"httpoison", "jason", "ecto"} {
		if !byName[name].Direct {
			t.Errorf("%s should be Direct=true in mix.exs", name)
		}
	}
}

func TestLoadEmptyDir(t *testing.T) {
	dir := t.TempDir()
	_, err := Load(dir)
	if err == nil {
		t.Error("expected error for directory with no Elixir lockfiles")
	}
}

// ---------------------------------------------------------------------------
// Capability detection tests
// ---------------------------------------------------------------------------

func TestDetectCapabilities(t *testing.T) {
	dir := t.TempDir()
	src := `defmodule MyApp do
  use HTTPoison.Base

  def run do
    System.cmd("ls", ["-la"])
  end

  def fetch(url) do
    HTTPoison.get(url)
  end
end
`
	if err := os.WriteFile(filepath.Join(dir, "my_app.ex"), []byte(src), 0o600); err != nil {
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
	src := `defmodule MyApp.Math do
  def add(a, b), do: a + b

  def greet(name) do
    "Hello, #{name}"
  end
end
`
	if err := os.WriteFile(filepath.Join(dir, "math.ex"), []byte(src), 0o600); err != nil {
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
	a := Adapter{}
	if a.Name() != "elixir" {
		t.Errorf("Name(): got %q, want %q", a.Name(), "elixir")
	}
}

func TestAdapterLoad(t *testing.T) {
	dir := t.TempDir()

	mixExs := `defmodule MyApp.MixProject do
  use Mix.Project

  defp deps do
    [
      {:httpoison, "~> 1.8"},
      {:jason, ">= 1.0.0"},
    ]
  end
end
`
	mixLock := `%{
  "httpoison": {:hex, :httpoison, "1.8.2", "aaa", [:mix], [{:certifi, "~> 2.9", []}, {:hackney, "~> 1.18", []}], "hexpm", "bbb"},
  "jason": {:hex, :jason, "1.4.1", "ccc", [:mix], [], "hexpm", "ddd"},
}
`
	if err := os.WriteFile(filepath.Join(dir, "mix.exs"), []byte(mixExs), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "mix.lock"), []byte(mixLock), 0o600); err != nil {
		t.Fatal(err)
	}

	a := Adapter{}
	g, err := a.Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if g == nil {
		t.Fatal("Load returned nil graph")
	}

	// Should have root module + at least the two deps.
	if len(g.Modules) < 2 {
		t.Errorf("expected at least 2 modules, got %d", len(g.Modules))
	}

	if _, ok := g.Packages["httpoison"]; !ok {
		t.Error("expected 'httpoison' package in graph")
	}
	if _, ok := g.Packages["jason"]; !ok {
		t.Error("expected 'jason' package in graph")
	}

	// httpoison should have network capability from import patterns.
	httpoisonPkg := g.Packages["httpoison"]
	if !httpoisonPkg.Capabilities.Has("network") {
		t.Error("expected httpoison to have 'network' capability")
	}
}

// ---------------------------------------------------------------------------
// Fuzz test
// ---------------------------------------------------------------------------

func FuzzParseMixLock(f *testing.F) {
	f.Add([]byte(`%{
  "bcrypt_elixir": {:hex, :bcrypt_elixir, "3.0.1", "abc", [:mix], [{:comeonin, "~> 5.3", []}], "hexpm", "def"},
}
`))
	f.Add([]byte(""))
	f.Add([]byte("%{}\n"))
	f.Add([]byte("# comment only\n"))
	f.Add([]byte(`%{
  "pkg": {:hex, :pkg, "1.0.0", "", [], [], "hexpm", ""},
}
`))

	f.Fuzz(func(t *testing.T, data []byte) {
		defer func() { recover() }() //nolint:errcheck

		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "mix.lock"), data, 0o600); err != nil {
			return
		}
		loadMixLock(dir) //nolint:errcheck
	})
}
