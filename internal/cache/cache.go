package cache

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

type entry struct {
	Expires time.Time `json:"expires"`
	Data    string    `json:"data"`
}

func cacheDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".cache", "gorisk"), nil
}

func keyPath(key string) (string, error) {
	dir, err := cacheDir()
	if err != nil {
		return "", err
	}
	if len(key) < 3 {
		return filepath.Join(dir, key), nil
	}
	return filepath.Join(dir, key[:2], key[2:]), nil
}

// Get retrieves cached data for the given key.
// Returns (data, true) if a valid non-expired entry exists.
func Get(key string) ([]byte, bool) {
	path, err := keyPath(key)
	if err != nil {
		return nil, false
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}

	var e entry
	if err := json.Unmarshal(raw, &e); err != nil {
		return nil, false
	}

	if time.Now().After(e.Expires) {
		return nil, false
	}

	data, err := base64.StdEncoding.DecodeString(e.Data)
	if err != nil {
		return nil, false
	}

	return data, true
}

// Set stores data for the given key with a TTL.
func Set(key string, data []byte, ttl time.Duration) error {
	path, err := keyPath(key)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}

	e := entry{
		Expires: time.Now().Add(ttl),
		Data:    base64.StdEncoding.EncodeToString(data),
	}

	raw, err := json.Marshal(e)
	if err != nil {
		return err
	}

	return os.WriteFile(path, raw, 0o600)
}
