package plugin

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPluginDirNonEmpty(t *testing.T) {
	d := PluginDir()
	if d == "" {
		t.Skip("no home dir available")
	}
	if !filepath.IsAbs(d) {
		t.Errorf("PluginDir() = %q, want absolute path", d)
	}
}

func TestLoadDirMissing(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nonexistent")
	loaded, errs := LoadDir(dir)
	if len(loaded) != 0 {
		t.Errorf("expected 0 loaded plugins, got %d", len(loaded))
	}
	if len(errs) != 0 {
		t.Errorf("expected 0 errors for missing dir, got %v", errs)
	}
}

func TestLoadDirEmpty(t *testing.T) {
	dir := t.TempDir()
	loaded, errs := LoadDir(dir)
	if len(loaded) != 0 {
		t.Errorf("expected 0 loaded plugins for empty dir, got %d", len(loaded))
	}
	if len(errs) != 0 {
		t.Errorf("expected 0 errors for empty dir, got %v", errs)
	}
}

func TestLoadDirIgnoresNonSO(t *testing.T) {
	dir := t.TempDir()
	// Write a .go file — should be ignored.
	if err := os.WriteFile(filepath.Join(dir, "plugin.go"), []byte("package main"), 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, errs := LoadDir(dir)
	if len(loaded) != 0 {
		t.Errorf("expected 0 loaded plugins (non-.so file), got %d", len(loaded))
	}
	if len(errs) != 0 {
		t.Errorf("unexpected errors: %v", errs)
	}
}

func TestLoadInvalidSO(t *testing.T) {
	dir := t.TempDir()
	soPath := filepath.Join(dir, "bad.so")
	// Write garbage bytes as a .so.
	if err := os.WriteFile(soPath, []byte("not a plugin"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, errs := LoadDir(dir)
	if len(errs) == 0 {
		t.Error("expected an error for invalid .so, got none")
	}
}
