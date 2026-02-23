package cache

import (
	"os"
	"testing"
	"time"
)

// overrideCacheDir points the cache at a temp directory for isolation.
func overrideCacheDir(t *testing.T) {
	t.Helper()
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)
	// Also set USERPROFILE for Windows compatibility, harmless on macOS/Linux.
	t.Setenv("USERPROFILE", tmp)
	// os.UserHomeDir() uses HOME on Unix; override is sufficient.
}

func TestSetGet(t *testing.T) {
	overrideCacheDir(t)

	key := "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"
	want := []byte("hello gorisk cache")

	if err := Set(key, want, time.Hour); err != nil {
		t.Fatalf("Set: %v", err)
	}

	got, ok := Get(key)
	if !ok {
		t.Fatal("Get returned false; expected cached value")
	}
	if string(got) != string(want) {
		t.Fatalf("Get returned %q; want %q", got, want)
	}
}

func TestExpiry(t *testing.T) {
	overrideCacheDir(t)

	key := "bbccddeeff00112233445566778899aabbccddeeff00112233445566778899aa"
	if err := Set(key, []byte("transient"), time.Millisecond); err != nil {
		t.Fatalf("Set: %v", err)
	}

	time.Sleep(5 * time.Millisecond)

	_, ok := Get(key)
	if ok {
		t.Fatal("Get returned true after TTL expiry; expected false")
	}
}

func TestKeyIsolation(t *testing.T) {
	overrideCacheDir(t)

	key1 := "1122334455667788990011223344556677889900112233445566778899001122"
	key2 := "2233445566778899001122334455667788990011223344556677889900112233"

	if err := Set(key1, []byte("value-one"), time.Hour); err != nil {
		t.Fatalf("Set key1: %v", err)
	}
	if err := Set(key2, []byte("value-two"), time.Hour); err != nil {
		t.Fatalf("Set key2: %v", err)
	}

	got1, ok1 := Get(key1)
	got2, ok2 := Get(key2)

	if !ok1 {
		t.Fatal("Get key1 returned false")
	}
	if !ok2 {
		t.Fatal("Get key2 returned false")
	}
	if string(got1) != "value-one" {
		t.Fatalf("key1: got %q; want %q", got1, "value-one")
	}
	if string(got2) != "value-two" {
		t.Fatalf("key2: got %q; want %q", got2, "value-two")
	}

	// Ensure a missing key returns false.
	_, ok3 := Get("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffx")
	if ok3 {
		t.Fatal("Get on absent key returned true")
	}
	_ = os.Remove // silence unused import lint if any
}
