package plugins

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRunListEmpty(t *testing.T) {
	// Point plugin dir at an empty temp dir.
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)

	code := Run([]string{"list"})
	if code != 0 {
		t.Errorf("Run(list) = %d, want 0", code)
	}
}

func TestRunUnknownSubcommand(t *testing.T) {
	code := Run([]string{"frobnicate"})
	if code != 2 {
		t.Errorf("Run(unknown) = %d, want 2", code)
	}
}

func TestRunNoArgs(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)
	code := Run(nil)
	if code != 0 {
		t.Errorf("Run(nil) = %d, want 0", code)
	}
}

func TestRunInstallMissingArg(t *testing.T) {
	code := Run([]string{"install"})
	if code != 2 {
		t.Errorf("Run(install no arg) = %d, want 2", code)
	}
}

func TestRunInstallAndRemove(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)

	// Create a fake .so file to install.
	src := filepath.Join(tmp, "myplugin.so")
	if err := os.WriteFile(src, []byte("fake plugin bytes"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Install it.
	code := Run([]string{"install", src})
	if code != 0 {
		t.Errorf("install returned %d, want 0", code)
	}

	// Second install without --force should fail.
	code = Run([]string{"install", src})
	if code != 1 {
		t.Errorf("second install (no --force) returned %d, want 1", code)
	}

	// Install with --force should succeed.
	code = Run([]string{"install", "--force", src})
	if code != 0 {
		t.Errorf("install --force returned %d, want 0", code)
	}

	// Remove it.
	code = Run([]string{"remove", "myplugin.so"})
	if code != 0 {
		t.Errorf("remove returned %d, want 0", code)
	}

	// Remove non-existent.
	code = Run([]string{"remove", "myplugin.so"})
	if code != 1 {
		t.Errorf("remove missing returned %d, want 1", code)
	}
}
