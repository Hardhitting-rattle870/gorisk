// Package serve implements the "gorisk serve" subcommand, which exposes gorisk's
// scan functionality as a simple HTTP/JSON API.
package serve

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/1homsi/gorisk/pkg/gorisk"
)

// Run is the entry point for "gorisk serve [--port 8080]".
func Run(args []string) int {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	port := fs.Int("port", 8080, "HTTP port to listen on")
	host := fs.String("host", "127.0.0.1", "IP address to bind")
	fs.Parse(args) //nolint:errcheck

	mux := http.NewServeMux()
	mux.HandleFunc("/health", handleHealth)
	mux.HandleFunc("/scan", handleScan)

	addr := fmt.Sprintf("%s:%d", *host, *port)
	server := &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 120 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	fmt.Fprintf(os.Stderr, "gorisk serve listening on http://%s\n", addr)
	fmt.Fprintln(os.Stderr, "  POST /scan   — run a risk scan")
	fmt.Fprintln(os.Stderr, "  GET  /health — server health check")

	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		fmt.Fprintln(os.Stderr, "serve error:", err)
		return 1
	}
	return 0
}

// ── /health ───────────────────────────────────────────────────────────────────

func handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"}) //nolint:errcheck
}

// ── /scan ─────────────────────────────────────────────────────────────────────

// scanRequest is the JSON body for POST /scan.
type scanRequest struct {
	Dir    string        `json:"dir"`
	Lang   string        `json:"lang"`
	Policy gorisk.Policy `json:"policy"`
}

// scanResponse wraps ScanResult for the HTTP response.
type scanResponse struct {
	*gorisk.ScanResult
	Error string `json:"error,omitempty"`
}

func handleScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req scanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}

	if req.Dir == "" {
		writeError(w, http.StatusBadRequest, "dir is required")
		return
	}

	// Validate the dir exists and is accessible.
	if _, err := os.Stat(req.Dir); err != nil {
		writeError(w, http.StatusBadRequest, "dir not accessible: "+err.Error())
		return
	}

	if req.Lang == "" {
		req.Lang = "auto"
	}
	if req.Policy.FailOn == "" {
		req.Policy = gorisk.DefaultPolicy()
	}

	scanner := gorisk.NewScanner(gorisk.ScanOptions{
		Dir:    req.Dir,
		Lang:   req.Lang,
		Policy: req.Policy,
	})

	result, err := scanner.Scan()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if !result.Passed {
		w.WriteHeader(http.StatusUnprocessableEntity) // 422
	}
	json.NewEncoder(w).Encode(scanResponse{ScanResult: result}) //nolint:errcheck
}

func writeError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(scanResponse{Error: msg}) //nolint:errcheck
}
