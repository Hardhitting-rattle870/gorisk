package serve

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHandleHealth(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()
	handleHealth(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("health status = %d, want 200", w.Code)
	}
	var body map[string]string
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("decode health response: %v", err)
	}
	if body["status"] != "ok" {
		t.Errorf(`health status field = %q, want "ok"`, body["status"])
	}
}

func TestHandleHealthMethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/health", nil)
	w := httptest.NewRecorder()
	handleHealth(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", w.Code)
	}
}

func TestHandleScanMethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/scan", nil)
	w := httptest.NewRecorder()
	handleScan(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", w.Code)
	}
}

func TestHandleScanBadJSON(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/scan", bytes.NewBufferString("not json"))
	w := httptest.NewRecorder()
	handleScan(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestHandleScanMissingDir(t *testing.T) {
	body, _ := json.Marshal(map[string]string{"lang": "go"})
	req := httptest.NewRequest(http.MethodPost, "/scan", bytes.NewReader(body))
	w := httptest.NewRecorder()
	handleScan(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestHandleScanInvalidDir(t *testing.T) {
	body, _ := json.Marshal(map[string]string{"dir": "/nonexistent/path/abc123"})
	req := httptest.NewRequest(http.MethodPost, "/scan", bytes.NewReader(body))
	w := httptest.NewRecorder()
	handleScan(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}
