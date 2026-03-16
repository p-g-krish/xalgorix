// Package web provides the Xalgorix web UI server.
package web

import (
	"bufio"
	"bytes"
	cryptorand "crypto/rand"
	"embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"log"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/xalgord/xalgorix/internal/agent"
	"github.com/xalgord/xalgorix/internal/config"
	"github.com/xalgord/xalgorix/internal/tools/notes"
	"github.com/xalgord/xalgorix/internal/tools/reporting"
)

const version = "0.10.2"

//go:embed static/*
var staticFiles embed.FS

// RateLimiter implements a simple in-memory rate limiter
type RateLimiter struct {
	mu       sync.Mutex
	requests map[string][]time.Time
	limit    int
	window   time.Duration
}

func NewRateLimiter(limit int, window time.Duration) *RateLimiter {
	rl := &RateLimiter{
		requests: make(map[string][]time.Time),
		limit:    limit,
		window:   window,
	}
	// Cleanup old entries every minute
	go func() {
		for {
			time.Sleep(time.Minute)
			rl.cleanup()
		}
	}()
	return rl
}

func (rl *RateLimiter) cleanup() {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := time.Now()
	for ip, times := range rl.requests {
		var valid []time.Time
		for _, t := range times {
			if now.Sub(t) < rl.window {
				valid = append(valid, t)
			}
		}
		if len(valid) == 0 {
			delete(rl.requests, ip)
		} else {
			rl.requests[ip] = valid
		}
	}
}

func (rl *RateLimiter) Allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := time.Now()
	windowStart := now.Add(-rl.window)
	
	// Get or create the slice
	times := rl.requests[ip]
	var valid []time.Time
	for _, t := range times {
		if t.After(windowStart) {
			valid = append(valid, t)
		}
	}
	
	if len(valid) >= rl.limit {
		rl.requests[ip] = valid
		return false
	}
	
	rl.requests[ip] = append(valid, now)
	return true
}

func rateLimitMiddleware(rl *RateLimiter) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Skip rate limiting for WebSocket and static files
			if r.URL.Path == "/ws" || strings.HasPrefix(r.URL.Path, "/static") {
				next.ServeHTTP(w, r)
				return
			}
			
			ip := r.RemoteAddr
			if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
				ip = strings.Split(forwarded, ",")[0]
			}
			
			if !rl.Allow(ip) {
				http.Error(w, "Rate limit exceeded. Please try again later.", http.StatusTooManyRequests)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

// ScanRequest is the JSON body for starting a scan.
type ScanRequest struct {
	Targets        []string `json:"targets"`
	Instruction    string   `json:"instruction"`
	ScanMode       string   `json:"scan_mode"`       // "single" or "wildcard"
	Model          string   `json:"model"`            // e.g. "minimax/MiniMax-M2.5"
	APIKey         string   `json:"api_key"`          // provider API key
	APIBase        string   `json:"api_base"`         // provider API base URL
	DiscordWebhook string   `json:"discord_webhook"` // Discord webhook URL
	SeverityFilter []string `json:"severity_filter"` // e.g. ["critical", "high"]
}

// WSEvent is a WebSocket message sent to clients.
type WSEvent struct {
	Type         string            `json:"type"`
	Content      string            `json:"content,omitempty"`
	ToolName     string            `json:"tool_name,omitempty"`
	ToolArgs     map[string]string `json:"tool_args,omitempty"`
	Output       string            `json:"output,omitempty"`
	Error        string            `json:"error,omitempty"`
	AgentID      string            `json:"agent_id,omitempty"`
	Timestamp    string            `json:"timestamp,omitempty"`
	Vulns        []VulnSummary     `json:"vulns,omitempty"`
	TargetIndex  int               `json:"target_index,omitempty"`
	TotalTargets int               `json:"total_targets,omitempty"`
	Target       string            `json:"target,omitempty"`
	TotalTokens  int               `json:"total_tokens,omitempty"`
}

// VulnSummary is a simplified vulnerability for the UI.
type VulnSummary struct {
	ID                string  `json:"id"`
	Title             string  `json:"title"`
	Severity          string  `json:"severity"`
	Endpoint          string  `json:"endpoint"`
	CVSS              float64 `json:"cvss"`
	Description       string  `json:"description,omitempty"`
	Impact            string  `json:"impact,omitempty"`
	Method            string  `json:"method,omitempty"`
	CVE               string  `json:"cve,omitempty"`
	TechnicalAnalysis string  `json:"technical_analysis,omitempty"`
	PoCDescription    string  `json:"poc_description,omitempty"`
	PoCScript         string  `json:"poc_script,omitempty"`
	Remediation       string  `json:"remediation,omitempty"`
}

// ScanRecord is a persisted scan result.
type ScanRecord struct {
	ID          string      `json:"id"`
	Target      string      `json:"target"`
	StartedAt   string      `json:"started_at"`
	FinishedAt  string      `json:"finished_at,omitempty"`
	Status      string      `json:"status"` // running, finished, stopped
	Events      []WSEvent   `json:"events"`
	Vulns       []VulnSummary `json:"vulns"`
	TotalTokens int         `json:"total_tokens"`
	Iterations  int         `json:"iterations"`
	ToolCalls   int         `json:"tool_calls"`
}

// QueueState persists scan queue state for recovery after restart
type QueueState struct {
	Targets     []string `json:"targets"`
	CurrentIdx  int      `json:"current_idx"`
	Instruction string   `json:"instruction"`
	ScanMode    string   `json:"scan_mode"`
	StartedAt   string   `json:"started_at"`
	Active      bool     `json:"active"`
}

// saveQueueState saves the current queue state to disk
func (s *Server) saveQueueState(targets []string, idx int, instruction, scanMode string) {
	state := QueueState{
		Targets:     targets,
		CurrentIdx:  idx,
		Instruction: instruction,
		ScanMode:    scanMode,
		StartedAt:   time.Now().Format(time.RFC3339),
		Active:      true,
	}
	data, _ := json.MarshalIndent(state, "", "  ")
	os.WriteFile(filepath.Join(s.dataDir, "queue_state.json"), data, 0644)
}

// loadQueueState loads queue state from disk if exists
func (s *Server) loadQueueState() *QueueState {
	data, err := os.ReadFile(filepath.Join(s.dataDir, "queue_state.json"))
	if err != nil {
		return nil
	}
	var state QueueState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil
	}
	return &state
}

// clearQueueState removes the queue state file
func (s *Server) clearQueueState() {
	os.Remove(filepath.Join(s.dataDir, "queue_state.json"))
}

// Server is the web UI server.
type Server struct {
	cfg            *config.Config
	port           int
	clients        map[*websocket.Conn]bool
	mu             sync.RWMutex
	agent          *agent.Agent
	running        bool
	stopReq        bool
	dataDir        string
	currentScanDir string
	discordWebhook string
	liveScanRecord *ScanRecord
	rateLimiter    *RateLimiter
	username       string
	password       string
}

// NewServer creates a new web server.
func NewServer(cfg *config.Config, port int) *Server {
	home, _ := os.UserHomeDir()
	dataDir := filepath.Join(home, "xalgorix-data", "scans")
	// Rate limit from config (defaults: 60 requests per minute)
	rl := NewRateLimiter(cfg.RateLimitRequests, time.Duration(cfg.RateLimitWindow)*time.Second)
	
	// Load auth credentials from environment
	username := os.Getenv("XALGORIX_USERNAME")
	password := os.Getenv("XALGORIX_PASSWORD")
	
	return &Server{
		cfg:            cfg,
		port:           port,
		clients:        make(map[*websocket.Conn]bool),
		dataDir:        dataDir,
		discordWebhook: os.Getenv("XALGORIX_DISCORD_WEBHOOK"),
		rateLimiter:    rl,
		username:       username,
		password:       password,
	}
}

// Start launches the web server.
func (s *Server) Start() error {
	s.initDataDir()

	staticFS, err := fs.Sub(staticFiles, "static")
	if err != nil {
		return fmt.Errorf("failed to load static files: %w", err)
	}

	// Auth middleware - wraps handler to require login
	authMiddleware := func(handler http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Skip auth if not configured
			if s.username == "" || s.password == "" {
				handler.ServeHTTP(w, r)
				return
			}
			
			// Check for auth cookie
			cookie, err := r.Cookie("xalgorix_auth")
			if err == nil && cookie.Value == s.username+":"+s.password {
				handler.ServeHTTP(w, r)
				return
			}
			
			// Check Basic Auth header
			auth := r.Header.Get("Authorization")
			if auth != "" {
				// Simple Basic Auth check
				encoded := strings.TrimPrefix(auth, "Basic ")
				decoded, err := base64.StdEncoding.DecodeString(encoded)
				if err == nil {
					creds := string(decoded)
					if creds == s.username+":"+s.password {
						handler.ServeHTTP(w, r)
						return
					}
				}
			}
			
			// Return 401 with login page
			w.Header().Set("WWW-Authenticate", `Basic realm="Xalgorix"`)
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`<!DOCTYPE html>
<html>
<head>
<title>Xalgorix - Login</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#0f172a;color:#e2e8f0;font-family:system-ui,sans-serif;min-height:100vh;display:flex;align-items:center;justify-content:center}
.card{background:#1e293b;padding:2rem;border-radius:12px;box-shadow:0 25px 50px -12px rgba(0,0,0,0.5);width:100%;max-width:400px}
h1{color:#00c896;margin-bottom:1.5rem;font-size:1.5rem}
input{width:100%;padding:12px;margin-bottom:1rem;background:#334155;border:1px solid #475569;border-radius:6px;color:#fff;font-size:1rem}
input:focus{outline:none;border-color:#00c896}
button{width:100%;padding:12px;background:#00c896;color:#0f172a;font-weight:600;border:none;border-radius:6px;cursor:pointer;font-size:1rem}
button:hover{background:#00b087}
.error{color:#ef4444;margin-bottom:1rem;font-size:0.875rem}
</style>
</head>
<body>
<div class="card">
<h1>🔒 Xalgorix Login</h1>
<form method="POST" action="/api/login">
<input type="text" name="username" placeholder="Username" required>
<input type="password" name="password" placeholder="Password" required>
<button type="submit">Login</button>
</form>
</div>
</body>
</html>`))
		})
	}

	mux := http.NewServeMux()
	// SPA handler: serve static files if they exist, otherwise serve index.html
	fileServer := http.FileServer(http.FS(staticFS))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Try to serve the static file
		path := r.URL.Path
		if path == "/" {
			fileServer.ServeHTTP(w, r)
			return
		}
		// Check if it's a real static file
		f, err := staticFS.(fs.ReadFileFS).ReadFile(path[1:]) // strip leading /
		if err == nil && f != nil {
			fileServer.ServeHTTP(w, r)
			return
		}
		// Not a static file — serve index.html (SPA catch-all)
		r.URL.Path = "/"
		fileServer.ServeHTTP(w, r)
	})
	mux.HandleFunc("/ws", s.handleWebSocket)
	mux.HandleFunc("/api/scan", s.handleScan)
	mux.HandleFunc("/api/stop", s.handleStop)
	mux.HandleFunc("/api/status", s.handleStatus)
	mux.HandleFunc("/api/scans", s.handleListScans)
	mux.HandleFunc("/api/scans/", s.handleGetScan)
	mux.HandleFunc("/api/upload-targets", s.handleUploadTargets)
	mux.HandleFunc("/api/upload-instructions", s.handleUploadInstructions)
	mux.HandleFunc("/api/report/", s.handleDownloadReport)
	mux.HandleFunc("/api/settings/rate-limit", s.handleRateLimit)
	mux.HandleFunc("/api/queue/status", s.handleQueueStatus)
	mux.HandleFunc("/api/queue/resume", s.handleQueueResume)
	mux.HandleFunc("/api/queue/clear", s.handleQueueClear)
	mux.HandleFunc("/api/version", s.handleVersion)
	mux.HandleFunc("/api/stop-notify", s.handleStopNotify)
	mux.HandleFunc("/api/login", s.handleLogin)
	mux.HandleFunc("/api/chat", s.handleChat)

	// Wrap with auth then rate limiting middleware
	rlMiddleware := rateLimitMiddleware(s.rateLimiter)
	
	addr := fmt.Sprintf("0.0.0.0:%d", s.port)
	log.Printf("Xalgorix Web UI → http://localhost:%d", s.port)
	log.Printf("Scan data → %s", s.dataDir)
	log.Printf("Rate limiting: %d requests/%ds per IP", s.cfg.RateLimitRequests, s.cfg.RateLimitWindow)
	if s.username != "" && s.password != "" {
		log.Printf("🔐 Authentication enabled")
	}
	return http.ListenAndServe(addr, rlMiddleware(authMiddleware(mux)))
}

// initDataDir creates the data directory and cleans up old scans (>30 days).
func (s *Server) initDataDir() {
	os.MkdirAll(s.dataDir, 0755)

	// Cleanup scans older than 30 days
	entries, _ := os.ReadDir(s.dataDir)
	cutoff := time.Now().AddDate(0, 0, -30)
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		if info.ModTime().Before(cutoff) {
			os.RemoveAll(filepath.Join(s.dataDir, e.Name()))
			log.Printf("Cleaned up old scan: %s", e.Name())
		}
	}

	// Check for interrupted queue and offer recovery
	if state := s.loadQueueState(); state != nil && state.Active {
		log.Printf("Found interrupted scan queue: %d targets remaining from index %d", 
			len(state.Targets)-state.CurrentIdx, state.CurrentIdx)
		// Queue will be offered for recovery via API
	}
}

func (s *Server) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("WebSocket upgrade error: %v", err)
		return
	}
	defer conn.Close()

	s.mu.Lock()
	s.clients[conn] = true
	s.mu.Unlock()

	defer func() {
		s.mu.Lock()
		delete(s.clients, conn)
		s.mu.Unlock()
	}()

	for {
		_, msg, err := conn.ReadMessage()
		if err != nil {
			break
		}

		var req ScanRequest
		if err := json.Unmarshal(msg, &req); err == nil && len(req.Targets) > 0 {
			go s.runMultiScan(req)
		}
	}
}

func (s *Server) handleScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}

	var req ScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}

	if len(req.Targets) == 0 {
		http.Error(w, "targets required", http.StatusBadRequest)
		return
	}

	// Apply LLM provider settings from web UI if provided
	if req.Model != "" {
		s.cfg.LLM = req.Model
	}
	if req.APIKey != "" {
		s.cfg.APIKey = req.APIKey
	}
	if req.APIBase != "" {
		s.cfg.APIBase = req.APIBase
	}

	go s.runMultiScan(req)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "started"})
}

func (s *Server) handleStop(w http.ResponseWriter, r *http.Request) {
	s.stopReq = true
	if s.agent != nil {
		s.agent.Stop()
	}
	s.running = false
	s.broadcast(WSEvent{Type: "stopped", Content: "Agent stopped by user"})
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "stopped"})
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	scanID := ""
	if s.currentScanDir != "" {
		scanID = filepath.Base(s.currentScanDir)
	}
	json.NewEncoder(w).Encode(map[string]any{
		"running": s.running,
		"scan_id": scanID,
		"vulns":   len(reporting.GetVulnerabilities()),
	})
}

// handleUploadTargets parses a text file with one target per line.
func (s *Server) handleUploadTargets(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}

	r.ParseMultipartForm(10 << 20) // 10MB max
	file, _, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "file required", http.StatusBadRequest)
		return
	}
	defer file.Close()

	var targets []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			targets = append(targets, line)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"targets": targets,
		"count":   len(targets),
	})
}

// handleUploadInstructions reads a text file and returns its content.
func (s *Server) handleUploadInstructions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}

	r.ParseMultipartForm(5 << 20) // 5MB max
	file, _, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "file required", http.StatusBadRequest)
		return
	}
	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		http.Error(w, "read error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"content": string(data),
	})
}

// randomSlug generates a short random hex string for scan IDs.
func randomSlug() string {
	b := make([]byte, 4)
	cryptorand.Read(b)
	return fmt.Sprintf("%x", b)
}

// sanitizeTarget creates a safe directory name from a target URL/domain.
func sanitizeTarget(target string) string {
	re := regexp.MustCompile(`[^a-zA-Z0-9._-]`)
	clean := re.ReplaceAllString(target, "_")
	clean = strings.TrimPrefix(clean, "https___")
	clean = strings.TrimPrefix(clean, "http___")
	clean = strings.Trim(clean, "_")
	if len(clean) > 60 {
		clean = clean[:60]
	}
	return clean
}

// runMultiScan processes targets sequentially, one at a time.
func (s *Server) runMultiScan(req ScanRequest) {
	if s.running {
		s.broadcast(WSEvent{Type: "error", Content: "A scan is already running"})
		return
	}

	s.running = true
	s.stopReq = false
	if req.DiscordWebhook != "" {
		s.discordWebhook = req.DiscordWebhook
	}
	totalTargets := len(req.Targets)

	// Save queue state for persistence
	s.saveQueueState(req.Targets, 0, req.Instruction, req.ScanMode)

	s.broadcast(WSEvent{
		Type:         "queue_started",
		Content:      fmt.Sprintf("Starting scan queue: %d target(s)", totalTargets),
		TotalTargets: totalTargets,
	})

	// Discord: scan started
	s.sendDiscord(0x00ff88, "🚀 Scan Started", fmt.Sprintf("**Targets:** %s\n**Mode:** %s\n**Total:** %d target(s)", strings.Join(req.Targets, ", "), req.ScanMode, totalTargets))

	for i, target := range req.Targets {
		if s.stopReq {
			s.broadcast(WSEvent{Type: "stopped", Content: "Scan queue stopped by user"})
			break
		}

		// Update queue state after each target
		s.saveQueueState(req.Targets, i, req.Instruction, req.ScanMode)

		// Create per-target scan directory with random slug
		scanDirName := fmt.Sprintf("%s_%s", sanitizeTarget(target), randomSlug())
		s.currentScanDir = filepath.Join(s.dataDir, scanDirName)
		os.MkdirAll(s.currentScanDir, 0755)

		// Build the instruction with scan mode context
		instruction := req.Instruction
		if req.ScanMode == "wildcard" {
			// PHASE 1: First do comprehensive subdomain enumeration
			discoveryInstruction := `PHASE 1: COMPREHENSIVE SUBDOMAIN ENUMERATION

Your ONLY task in this phase is to discover ALL subdomains. Do NOT run any vulnerability scans yet.

Execute these commands in order and save ALL results:

# Passive subdomain enumeration (no direct contact)
1. subfinder -d TARGET -passive -o ~/xalgorix-data/passive_subfinder.txt
2. curl -s "https://crt.sh/?q=%.TARGET&output=json" | jq -r '.[].name_value' 2>/dev/null | sort -u > ~/xalgorix-data/passive_crt.txt
3. findomain -t TARGET --output ~/xalgorix-data/passive_findomain.txt 2>/dev/null || true
4. assetfinder --subs-only TARGET | tee ~/xalgorix-data/passive_assetfinder.txt 2>/dev/null || true
5. curl -s "https://dns.bufferover.run/dns?q=.TARGET" | jq -r '.FDNS_A[]' 2>/dev/null | cut -d',' -f2 | sort -u > ~/xalgorix-data/passive_dnsbufferover.txt

# Archive enumeration
6. curl -s "https://web.archive.org/cdx/search/cdx?url=*.TARGET/*&output=json&fl=original&filter=statuscode:200" | jq -r '.[].original' 2>/dev/null | cut -d'/' -f3 | sort -u > ~/xalgorix-data/archive_subdomains.txt

# Active subdomain enumeration (direct contact)
7. subfinder -d TARGET -all -recursive -o ~/xalgorix-data/active_subfinder.txt
8. subfinder -d TARGET -w /usr/share/wordlists/subdomains.txt -o ~/xalgorix-data/active_bruteforce.txt 2>/dev/null || true
9. amass enum -d TARGET -active -o ~/xalgorix-data/active_amass.txt 2>/dev/null || true

# Merge ALL subdomains
10. cat ~/xalgorix-data/passive_*.txt ~/xalgorix-data/active_*.txt ~/xalgorix-data/archive_subdomains.txt 2>/dev/null | grep -v '*' | sort -u > ~/xalgorix-data/all_discovered_subdomains.txt
11. wc -l ~/xalgorix-data/all_discovered_subdomains.txt

# Resolve subdomains to find live hosts
12. cat ~/xalgorix-data/all_discovered_subdomains.txt | dnsx -silent -a -resp -o ~/xalgorix-data/live_resolved.txt 2>/dev/null || true
13. cat ~/xalgorix-data/live_resolved.txt | cut -d' ' -1 | grep -v '^$' | sort -u > ~/xalgorix-data/live_subdomains.txt
14. wc -l ~/xalgorix-data/live_subdomains.txt

# IMPORTANT: After completing subdomain enumeration, you MUST call add_note with the full list of discovered subdomains (from ~/xalgorix-data/live_subdomains.txt) so they can be queued for individual scanning.

STOP HERE. Do NOT proceed to vulnerability scanning. The system will now queue each discovered subdomain for comprehensive vulnerability assessment.`

			s.broadcast(WSEvent{
				Type:         "target_started",
				Content:      fmt.Sprintf("[PHASE 1] Discovering subdomains for: %s", target),
				Target:       target,
				AgentID:      filepath.Base(s.currentScanDir),
				TargetIndex:  i + 1,
				TotalTargets: totalTargets,
			})

			// Run discovery phase
			s.runSingleScan([]string{target}, discoveryInstruction, req.SeverityFilter)

			// Read discovered subdomains from file
			subdomainsFile := filepath.Join(s.dataDir, "live_subdomains.txt")
			subdomainsData, err := os.ReadFile(subdomainsFile)
			var subdomains []string
			if err == nil {
				for _, line := range strings.Split(string(subdomainsData), "\n") {
					line = strings.TrimSpace(line)
					if line != "" && !strings.Contains(line, " ") {
						subdomains = append(subdomains, line)
					}
				}
			}

			// If no subdomains found, try alternative files
			if len(subdomains) == 0 {
				altFile := filepath.Join(s.dataDir, "all_discovered_subdomains.txt")
				if data, err := os.ReadFile(altFile); err == nil {
					for _, line := range strings.Split(string(data), "\n") {
						line = strings.TrimSpace(line)
						if line != "" && !strings.Contains(line, "*") {
							subdomains = append(subdomains, line)
						}
					}
				}
			}

			s.broadcast(WSEvent{
				Type:         "target_completed",
				Content:      fmt.Sprintf("[PHASE 1] Discovery complete: found %d subdomains. Now scanning each individually.", len(subdomains)),
				Target:       target,
				TargetIndex:  i + 1,
				TotalTargets: totalTargets,
			})

			// PHASE 2: Scan each subdomain individually with comprehensive vulnerability testing
			for j, subdomain := range subdomains {
				if s.stopReq {
					s.broadcast(WSEvent{Type: "stopped", Content: "Scan queue stopped by user"})
					break
				}

				// Update queue state
				s.saveQueueState([]string{target}, i, req.Instruction, req.ScanMode)

				// Create scan directory for this subdomain
				scanDirName = fmt.Sprintf("%s_%s", sanitizeTarget(subdomain), randomSlug())
				s.currentScanDir = filepath.Join(s.dataDir, scanDirName)
				os.MkdirAll(s.currentScanDir, 0755)

				// Build comprehensive single-target instruction
				scanInstruction := fmt.Sprintf(`PHASE 2: COMPREHENSIVE VULNERABILITY SCAN ON: %s

This is a SINGLE TARGET vulnerability assessment. You have unlimited iterations. Think DEEPER than automated tools - they only find the obvious.

TARGET: %s

## CRITICAL: THINK OUT OF THE BOX
Automated tools miss 80%% of vulnerabilities. You must think and test MANUALLY:
1. What is this application's BUSINESS LOGIC? Understand how it works.
2. What happens if I manipulate this request in UNEXPECTED ways?
3. What if this parameter is used in a DIFFERENT context than intended?
4. What hidden functionality might exist that tools don't find?
5. Can I chain multiple low-severity findings into a CRITICAL chain?

## TOOLS ARE JUST A START - THINK AFTER THEM
Tools find obvious bugs. YOU find the complex ones. After each tool:
- Ask: "What did this MISS?"
- Try variations the tool didn't test
- Test edge cases and unexpected inputs
- Look for race conditions, timing vulnerabilities
- Check for business logic flaws

Perform these phases in order:

## PHASE 2A: DEEP RECON (THINK while scanning)
- nmap -sV -sC -T4 -A -p- --open -oN ~/xalgorix-data/nmap.txt https://%s
- whatweb -v -a 3 https://%s 2>/dev/null
- httpx -silent -status-code -title -tech-detect -follow-redirects -o ~/xalgorix-data/httpx.txt

THEN THINK: What technologies did you find? What are their known vulnerabilities? Research CVE for these versions!

## PHASE 2B: DEEP CRAWLING (beyond what tools see)
- gospider -s https://%s --depth 3 -o ~/xalgorix-data/gospider/ 2>/dev/null
- katana -u https://%s -d 5 -jc -kf -ef css,png,jpg -o ~/xalgorix-data/katana.txt 2>/dev/null
- gau %s --threads 5 -o ~/xalgorix-data/gau.txt
- waybackurls %s | sort -u | tee ~/xalgorix-data/wayback.txt

THEN MANUALLY CHECK:
- Are there admin panels, debug endpoints, backup files?
- Check for exposed .git, .env, config files, .swp
- Look for old versions at /old, /backup, /v1, /api/v1
- Check for debug mode: /debug, /trace, /health

## PHASE 2C: PARAMETER DISCOVERY (find hidden params)
- paramspider -d %s -o ~/xalgorix-data/params.txt 2>/dev/null || true
- arjun -u https://%s -m GET -w ~/wordlists parameters.txt -t 20 -o ~/xalgorix-data/arjun.txt 2>/dev/null || true

THEN MANUALLY FIND MORE:
- Check common param names: id, user, file, q, search, query, token, key, secret
- Try HTTP methods: PUT, DELETE, PATCH on all endpoints
- Test headers: X-Forwarded-For, X-Real-IP, X-API-Key, Authorization
- Test cookies as inputs

## PHASE 2D: CREATIVE VULNERABILITY TESTING
Test with YOUR BRAIN - not just tools:

### SQL Injection - THINK:
- Tools test basic payloads. You test: TIME-based, STACKED queries, second-order, UNION on non-integer IDs
- Try: admin'--, admin' or 1=1--, ' waitfor delay
- Test in headers, cookies, user-agent
- Bypass: /**/, %00, null bytes, encoding variations

### XSS - THINK:
- Tools miss DOM-based, Stored with filters
- Try: <script>alert(1)</script> but also: <img src=x onerror=alert(1)>, <svg onload=alert(1)>
- Test in URL fragments (#), referer, user-agent
- Bypass: <scr\x00ipt>, <ScRiPt>, event handlers tools miss

### SSRF - THINK:
- Tools test basic URLs. You test: internal IPs, cloud metadata, port scanning
- Try: http://169.254.169.254/latest/meta-data/, http://localhost:port
- Test via Referer, X-Forwarded-For

### IDOR - THINK:
- Not just ID=1 vs ID=2 - test UUIDs, emails, usernames
- Test horizontal and vertical privilege escalation
- Check if changing JSON keys reveals more data

### RCE/Command Injection - THINK:
- Test in every input: headers, cookies, params, filenames
- Try: ;whoami, |whoami, $(whoami), commandInjection, %0a
- Test for blind RCE with time delays

## PHASE 2E: BUSINESS LOGIC TESTING (think like an attacker)
- Can you bypass payment/discounts?
- Can you manipulate quantity to negative?
- Can you access other users' data by changing IDs?
- Can you escalate privileges?
- Can you bypass rate limits?
- Can you trigger race conditions?

## PHASE 2F: MANUAL EXPLOITATION
For each finding, MANUALLY exploit:
- SQLi: Extract data, don't just confirm
- XSS: Try cookie theft, keylogging
- SSRF: Access cloud metadata, internal services
- Auth bypass: Create admin account, access admin panel
- IDOR: View all data, not just one user's

Document EVERYTHING in add_note. THINK before each test. Automated tools are dumb - YOU are smart.`, subdomain, subdomain, subdomain, subdomain, subdomain, subdomain, subdomain, subdomain, subdomain)

				s.broadcast(WSEvent{
					Type:         "target_started",
					Content:      fmt.Sprintf("[PHASE 2] Scanning subdomain %d/%d: %s", j+1, len(subdomains), subdomain),
					Target:       subdomain,
					AgentID:      filepath.Base(s.currentScanDir),
					TargetIndex:  j + 1,
					TotalTargets: len(subdomains),
				})

				s.runSingleScan([]string{subdomain}, scanInstruction, req.SeverityFilter)

				s.broadcast(WSEvent{
					Type:         "target_completed",
					Content:      fmt.Sprintf("[PHASE 2] Subdomain %d/%d completed: %s", j+1, len(subdomains), subdomain),
					Target:       subdomain,
					TargetIndex:  j + 1,
					TotalTargets: len(subdomains),
				})
			}

			continue // Skip the regular scan below since we did wildcard handling above
		} else if req.ScanMode == "dast" {
			// DAST mode - scan specific URLs (not subdomains)
			// Build comprehensive DAST instruction for URL scanning
			dastInstruction := fmt.Sprintf(`DAST (Dynamic Application Security Testing) ON: %s

This is a URL-LEVEL vulnerability assessment. You are testing a specific URL, not a domain or subdomain.

TARGET URL: %s

## CRITICAL: DAST MODE RULES
- Do NOT scan for subdomains - only test THIS exact URL
- Do NOT run nmap/subfinder/amass - they are for recon, not DAST
- Focus on the URL provided, its parameters, and endpoints it reveals

## PHASE 1: URL ANALYSIS
- Send a request and analyze the response
- Identify: parameters, forms, headers, cookies, HTTP methods supported
- Check for interesting headers: Server, X-Powered-By, X-Framework
- Note all input fields, even hidden ones

## PHASE 2: CRAWL THE APPLICATION (from this URL)
- Use tools to discover more endpoints FROM this URL:
  - gospider -s %s --depth 2
  - katana -u %s -d 3 -jc
  - hakrawler -url %s -depth 2
- Collect ALL URLs discovered

## PHASE 3: PARAMETER DISCOVERY
- Find ALL parameters in all discovered URLs
- Use: paramspider -u %s
- Use: arjun -u %s -m GET

## PHASE 4: VULNERABILITY TESTING (TEST EVERY PARAMETER)
For EACH parameter found, test:

### SQL Injection
- ' OR '1'='1, admin'--, ' UNION SELECT--
- Test with time delays: '; WAITFOR DELAY
- Test in GET, POST, headers, cookies

### XSS
- <script>alert(1)</script>, <img src=x onerror=alert(1)>
- Test in URL params, form fields, headers

### SSRF
- http://localhost, http://127.0.0.1
- http://169.254.169.254 (cloud metadata)
- Test in every URL parameter

### Command Injection
- ;whoami, |whoami, $(whoami)
- Test in filename params, search params

### LFI/Path Traversal
- ../../../../etc/passwd, ..\\..\\..\\windows\\system32

### IDOR
- Change IDs, UUIDs, usernames in URLs
- Test horizontal and vertical privilege

## PHASE 5: NUCLEI DAST (Run on URLs ONLY!)
**IMPORTANT: Run nuclei on discovered URLs, NOT on the main domain!**

After crawling, you have a list of URLs in ~/xalgorix-data/*.txt
- Run nuclei on each URL file:
  - nuclei -l ~/xalgorix-data/gospider/*.txt -dast -severity critical,high,medium -o ~/xalgorix-data/nuclei_dast.txt
  - nuclei -l ~/xalgorix-data/katana.txt -dast -severity critical,high -o ~/xalgorix-data/nuclei_katana.txt
  - nuclei -l ~/xalgorix-data/gau.txt -dast -severity critical,high,medium -o ~/xalgorix-data/nuclei_gau.txt
  - nuclei -l ~/xalgorix-data/wayback.txt -dast -severity critical,high -o ~/xalgorix-data/nuclei_wayback.txt

DO NOT run: nuclei -u TARGET (that scans the main domain only!)

## PHASE 6: MANUAL EXPLOITATION
For each finding, manually exploit to prove impact:
- Extract data with SQLi
- Steal cookies with XSS
- Access internal services with SSRF

THINK OUT OF THE BOX - tools miss 80%% of bugs!

Document everything in add_note.`, target, target, target, target, target)

			s.broadcast(WSEvent{
				Type:         "target_started",
				Content:      fmt.Sprintf("[DAST] Scanning URL: %s", target),
				Target:       target,
				AgentID:      filepath.Base(s.currentScanDir),
				TargetIndex:  i + 1,
				TotalTargets: totalTargets,
			})

			s.runSingleScan([]string{target}, dastInstruction, req.SeverityFilter)

			s.broadcast(WSEvent{
				Type:         "target_completed",
				Content:      fmt.Sprintf("[DAST] Completed: %s", target),
				Target:       target,
				TargetIndex:  i + 1,
				TotalTargets: totalTargets,
			})
			continue
		} else {
			// Single site mode - explicitly tell agent to NOT do subdomain enumeration
			instruction = "This is a SINGLE TARGET scan. Do NOT enumerate subdomains or perform wildcard discovery. Only test the exact target URL provided. Focus on the main domain/IP only. " + instruction
		}

		s.broadcast(WSEvent{
			Type:         "target_started",
			Content:      fmt.Sprintf("Scanning target %d/%d: %s", i+1, totalTargets, target),
			Target:       target,
			AgentID:      filepath.Base(s.currentScanDir),
			TargetIndex:  i + 1,
			TotalTargets: totalTargets,
		})

		s.runSingleScan([]string{target}, instruction, req.SeverityFilter)

		s.broadcast(WSEvent{
			Type:         "target_completed",
			Content:      fmt.Sprintf("Target %d/%d completed: %s", i+1, totalTargets, target),
			Target:       target,
			TargetIndex:  i + 1,
			TotalTargets: totalTargets,
		})
	}

	// Clear queue state when done
	s.clearQueueState()
	s.running = false

	// Discord: scan finished with PDF
	vulns := reporting.GetVulnerabilities()
	
	// Generate PDF report
	reportPath := ""
	if s.liveScanRecord != nil {
		s.liveScanRecord.Status = "finished"
		s.liveScanRecord.FinishedAt = time.Now().Format(time.RFC3339)
		s.liveScanRecord.Vulns = vulnSummaries(vulns)
		if p, err := s.generateReport(s.liveScanRecord); err == nil {
			reportPath = p
		}
	}
	
	// Send Discord with PDF
	desc := fmt.Sprintf("**Targets:** %d completed\n**Vulnerabilities:** %d found\n**Completed at:** %s", totalTargets, len(vulns), time.Now().Format("15:04:05 MST"))
	if reportPath != "" {
		s.sendDiscordWithFile(0x3b82f6, "✅ Scan Finished - Report Ready", desc, reportPath)
	} else {
		s.sendDiscord(0x3b82f6, "✅ Scan Finished", desc)
	}

	s.broadcast(WSEvent{
		Type:    "queue_finished",
		Content: fmt.Sprintf("All %d target(s) completed", totalTargets),
	})
}

func (s *Server) runSingleScan(targets []string, instruction string, severityFilter []string) {
	// Reset global state from previous scans
	reporting.ResetVulnerabilities()
	notes.ResetNotes()

	events := make(chan agent.Event, 512)
	s.agent = agent.NewAgent(s.cfg, "XalgorixAgent", events)

	// Initialize scan record for persistence
	scanRecord := ScanRecord{
		ID:        filepath.Base(s.currentScanDir),
		Target:    strings.Join(targets, ", "),
		StartedAt: time.Now().Format(time.RFC3339),
		Status:    "running",
		Events:    []WSEvent{},
		Vulns:     []VulnSummary{},
	}

	// Save initial scan record
	s.liveScanRecord = &scanRecord
	s.saveScanRecord(&scanRecord)

	done := make(chan struct{})
	go func() {
		defer close(done)
		for evt := range events {
			wsEvt := WSEvent{
				Type:        evt.Type,
				Content:     evt.Content,
				ToolName:    evt.ToolName,
				ToolArgs:    evt.ToolArgs,
				AgentID:     evt.AgentID,
				Timestamp:   evt.Timestamp.Format(time.RFC3339),
				TotalTokens: evt.TotalTokens,
			}

			if evt.Type == "tool_result" {
				wsEvt.Output = evt.ToolResult.Output
				wsEvt.Error = evt.ToolResult.Error

				// Push vuln to UI in real-time when report_vulnerability succeeds
				if evt.ToolName == "report_vulnerability" && evt.ToolResult.Error == "" {
					vulns := reporting.GetVulnerabilities()
					if len(vulns) > 0 {
						latest := vulns[len(vulns)-1]
						vs := vulnToSummary(latest)
						wsEvt.Vulns = []VulnSummary{vs}
						scanRecord.Vulns = append(scanRecord.Vulns, vs)

						// Discord: vulnerability found
						sevColor := 0xef4444 // red for critical/high
						switch vs.Severity {
						case "medium":
							sevColor = 0xd97706
						case "low", "info":
							sevColor = 0x3b82f6
						}
						// Build detailed description with all available fields
						var details strings.Builder
						details.WriteString(fmt.Sprintf("**%s**\n\n", vs.Title))
						if vs.Description != "" {
							details.WriteString(fmt.Sprintf("📝 **Description:**\n%s\n\n", vs.Description))
						}
						if vs.Endpoint != "" {
							details.WriteString(fmt.Sprintf("🔗 **Endpoint:** `%s`\n", vs.Endpoint))
						}
						if vs.Method != "" {
							details.WriteString(fmt.Sprintf("📡 **Method:** `%s`\n", vs.Method))
						}
						if vs.CVE != "" {
							details.WriteString(fmt.Sprintf("🏷️ **CVE:** `%s`\n", vs.CVE))
						}
						details.WriteString(fmt.Sprintf("📊 **CVSS:** `%.1f` | **Severity:** `%s`\n\n", vs.CVSS, strings.ToUpper(vs.Severity)))
						if vs.Impact != "" {
							details.WriteString(fmt.Sprintf("💥 **Impact:**\n%s\n\n", vs.Impact))
						}
						if vs.TechnicalAnalysis != "" {
							details.WriteString(fmt.Sprintf("🔬 **Technical Analysis:**\n%s\n\n", vs.TechnicalAnalysis))
						}
						if vs.PoCDescription != "" {
							details.WriteString(fmt.Sprintf("🧪 **PoC:**\n%s\n", vs.PoCDescription))
						}
						if vs.PoCScript != "" {
							// Truncate PoC script for Discord (max 1024 per field)
							poc := vs.PoCScript
							if len(poc) > 800 {
								poc = poc[:800] + "\n... (truncated)"
							}
							details.WriteString(fmt.Sprintf("```\n%s\n```\n\n", poc))
						}
						if vs.Remediation != "" {
							details.WriteString(fmt.Sprintf("🛡️ **Remediation:**\n%s", vs.Remediation))
						}
						s.sendDiscord(sevColor, fmt.Sprintf("🐛 %s Vulnerability Found", strings.ToUpper(vs.Severity)), details.String())
					}
				}
			}

			if evt.Type == "finished" {
				vulns := reporting.GetVulnerabilities()
				for _, v := range vulns {
					wsEvt.Vulns = append(wsEvt.Vulns, vulnToSummary(v))
				}
			}

			// Track stats
			if evt.Type == "thinking" {
				scanRecord.Iterations++
			}
			if evt.Type == "tool_call" {
				scanRecord.ToolCalls++
			}
			if evt.TotalTokens > 0 {
				scanRecord.TotalTokens = evt.TotalTokens
			}

			// Accumulate events for persistence (limit stored output size)
			savedEvt := wsEvt
			if len(savedEvt.Output) > 500 {
				savedEvt.Output = savedEvt.Output[:500] + "..."
			}
			scanRecord.Events = append(scanRecord.Events, savedEvt)

			// Periodically save scan record (every 10 events)
			if len(scanRecord.Events)%10 == 0 {
				s.saveScanRecord(&scanRecord)
			}

			s.broadcast(wsEvt)
		}
	}()

	// Add severity filter to instruction if specified
	if len(severityFilter) > 0 {
		severityText := "CRITICAL INSTRUCTION: You MUST ONLY look for and report "
		
		// Build severity list
		severities := make([]string, len(severityFilter))
		copy(severities, severityFilter)
		severityText += strings.Join(severities, " and ") + " severity vulnerabilities. "
		severityText += "DO NOT report, investigate, or mention any LOW severity, INFORMATIONAL, or INFO findings. "
		severityText += "Ignore any potential LOW/INFO issues - they are out of scope for this engagement. "
		severityText += "Focus ONLY on: " + strings.Join(severities, ", ") + "."
		instruction = severityText + "\n\n" + instruction
	}

	s.agent.Run(targets, instruction)
	close(events)
	<-done

	// Finalize scan record
	scanRecord.Status = "finished"
	scanRecord.FinishedAt = time.Now().Format(time.RFC3339)

	// Save final vulns from reporting module
	scanRecord.Vulns = nil
	for _, v := range reporting.GetVulnerabilities() {
		scanRecord.Vulns = append(scanRecord.Vulns, vulnToSummary(v))
	}

	s.saveScanRecord(&scanRecord)
	s.liveScanRecord = nil

	// Generate PDF report
	reportPath, err := s.generateReport(&scanRecord)
	if err != nil {
		log.Printf("Failed to generate PDF report: %v", err)
		s.sendDiscord(0x3b82f6, "✅ Scan Finished", fmt.Sprintf("**Target:** %s\n**Vulnerabilities:** %d found\n**Completed at:** %s (PDF generation failed)", scanRecord.Target, len(scanRecord.Vulns), time.Now().Format("15:04:05 MST")))
	} else {
		log.Printf("PDF report saved: %s", reportPath)
		// Send Discord with PDF
		desc := fmt.Sprintf("**Target:** %s\n**Vulnerabilities:** %d found\n**Completed at:** %s", scanRecord.Target, len(scanRecord.Vulns), time.Now().Format("15:04:05 MST"))
		s.sendDiscordWithFile(0x3b82f6, "✅ Scan Finished - Report Ready", desc, reportPath)
		// Notify via WebSocket that report is ready
		s.broadcast(WSEvent{
			Type:    "report_ready",
			Content: fmt.Sprintf("/api/report/%s", scanRecord.ID),
		})
	}
}

// vulnToSummary converts a reporting.Vulnerability to a VulnSummary with all fields.
func vulnToSummary(v reporting.Vulnerability) VulnSummary {
	return VulnSummary{
		ID:                v.ID,
		Title:             v.Title,
		Severity:          v.Severity,
		Endpoint:          v.Endpoint,
		CVSS:              v.CVSS,
		Description:       v.Description,
		Impact:            v.Impact,
		Method:            v.Method,
		CVE:               v.CVE,
		TechnicalAnalysis: v.TechnicalAnalysis,
		PoCDescription:    v.PoCDescription,
		PoCScript:         v.PoCScript,
		Remediation:       v.Remediation,
	}
}

// vulnSummaries converts a slice of vulnerabilities to VulnSummary
func vulnSummaries(vulns []reporting.Vulnerability) []VulnSummary {
	result := make([]VulnSummary, len(vulns))
	for i, v := range vulns {
		result[i] = vulnToSummary(v)
	}
	return result
}

func (s *Server) saveScanRecord(rec *ScanRecord) {
	if s.currentScanDir == "" {
		return
	}
	data, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return
	}
	os.WriteFile(filepath.Join(s.currentScanDir, "scan.json"), data, 0644)
}

// handleListScans returns a list of all saved scans (sorted newest first).
func (s *Server) handleListScans(w http.ResponseWriter, r *http.Request) {
	entries, _ := os.ReadDir(s.dataDir)

	type scanInfo struct {
		ID          string `json:"id"`
		Target      string `json:"target"`
		StartedAt   string `json:"started_at"`
		Status      string `json:"status"`
		VulnCount   int    `json:"vuln_count"`
		TotalTokens int    `json:"total_tokens"`
	}

	var scans []scanInfo
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		scanPath := filepath.Join(s.dataDir, e.Name(), "scan.json")
		data, err := os.ReadFile(scanPath)
		if err != nil {
			continue
		}
		var rec ScanRecord
		if json.Unmarshal(data, &rec) != nil {
			continue
		}
		scans = append(scans, scanInfo{
			ID:          rec.ID,
			Target:      rec.Target,
			StartedAt:   rec.StartedAt,
			Status:      rec.Status,
			VulnCount:   len(rec.Vulns),
			TotalTokens: rec.TotalTokens,
		})
	}

	// Sort newest first
	sort.Slice(scans, func(i, j int) bool {
		return scans[i].StartedAt > scans[j].StartedAt
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(scans)
}

// handleDownloadReport serves the PDF report for a scan.
func (s *Server) handleDownloadReport(w http.ResponseWriter, r *http.Request) {
	scanID := strings.TrimPrefix(r.URL.Path, "/api/report/")
	if scanID == "" {
		http.Error(w, "scan ID required", http.StatusBadRequest)
		return
	}

	reportPath := filepath.Join(s.dataDir, scanID, fmt.Sprintf("xalgorix_report_%s.pdf", scanID))

	// If report doesn't exist, try to generate it
	if _, err := os.Stat(reportPath); os.IsNotExist(err) {
		// Load scan record
		scanPath := filepath.Join(s.dataDir, scanID, "scan.json")
		data, err := os.ReadFile(scanPath)
		if err != nil {
			http.Error(w, "scan not found", http.StatusNotFound)
			return
		}
		var rec ScanRecord
		if err := json.Unmarshal(data, &rec); err != nil {
			http.Error(w, "invalid scan data", http.StatusInternalServerError)
			return
		}
		if _, err := s.generateReport(&rec); err != nil {
			log.Printf("Report generation error: %v", err)
			http.Error(w, "failed to generate report: "+err.Error(), http.StatusInternalServerError)
			return
		}
	}

	w.Header().Set("Content-Type", "application/pdf")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"xalgorix_report_%s.pdf\"", scanID))
	http.ServeFile(w, r, reportPath)
}

// handleRateLimit handles GET and POST for rate limit settings.
func (s *Server) handleRateLimit(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	
	switch r.Method {
	case "GET":
		// Return current rate limit settings
		json.NewEncoder(w).Encode(map[string]int{
			"requests": s.cfg.RateLimitRequests,
			"window":   s.cfg.RateLimitWindow,
		})
		
	case "POST":
		// Update rate limit settings
		var req struct {
			Requests int `json:"requests"`
			Window   int `json:"window"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		
		// Validate values
		if req.Requests < 1 {
			req.Requests = 1
		}
		if req.Requests > 1000 {
			req.Requests = 1000
		}
		if req.Window < 10 {
			req.Window = 10
		}
		if req.Window > 3600 {
			req.Window = 3600
		}
		
		// Update config
		s.cfg.RateLimitRequests = req.Requests
		s.cfg.RateLimitWindow = req.Window
		
		// Recreate rate limiter with new settings
		s.rateLimiter = NewRateLimiter(req.Requests, time.Duration(req.Window)*time.Second)
		
		log.Printf("Rate limiting updated: %d requests/%ds per IP", req.Requests, req.Window)
		
		json.NewEncoder(w).Encode(map[string]int{
			"requests": req.Requests,
			"window":   req.Window,
		})
		
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleVersion returns the current Xalgorix version
func (s *Server) handleVersion(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"version": version,
	})
}

// handleStopNotify sends a stop notification to Discord if a scan was running
func (s *Server) handleStopNotify(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	
	// Send Discord notification if webhook is configured
	if s.discordWebhook != "" {
		s.sendDiscord(0xff6b6b, "🛑 Xalgorix Stopped", "The Xalgorix service has been stopped by the user.")
	}
	
	json.NewEncoder(w).Encode(map[string]string{"status": "notified"})
}

// handleLogin processes login form submission
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	
	username := r.FormValue("username")
	password := r.FormValue("password")
	
	if username == s.username && password == s.password {
		// Set auth cookie
		http.SetCookie(w, &http.Cookie{
			Name:     "xalgorix_auth",
			Value:    username + ":" + password,
			Path:     "/",
			HttpOnly: true,
			MaxAge:   86400 * 7, // 7 days
		})
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	} else {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid credentials"})
	}
}

// handleChat allows users to send messages to the agent during a scan
type ChatRequest struct {
	Message string `json:"message"`
}

func (s *Server) handleChat(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req ChatRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	if req.Message == "" {
		http.Error(w, "message is required", http.StatusBadRequest)
		return
	}

	// Check if there's an active scan
	if s.agent == nil {
		http.Error(w, "no active scan", http.StatusBadRequest)
		return
	}

	// Send the message to the agent
	response, err := s.agent.SendMessage(req.Message)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"response": response,
	})
}

// handleQueueStatus returns the current queue state for recovery
func (s *Server) handleQueueStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	
	if state := s.loadQueueState(); state != nil && state.Active {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"available":      true,
			"targets":        state.Targets,
			"current_idx":    state.CurrentIdx,
			"remaining":      len(state.Targets) - state.CurrentIdx,
			"instruction":    state.Instruction,
			"scan_mode":     state.ScanMode,
			"started_at":    state.StartedAt,
		})
	} else {
		json.NewEncoder(w).Encode(map[string]bool{"available": false})
	}
}

// handleQueueResume resumes an interrupted scan queue
func (s *Server) handleQueueResume(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	
	if s.running {
		json.NewEncoder(w).Encode(map[string]string{"error": "A scan is already running"})
		return
	}
	
	state := s.loadQueueState()
	if state == nil || !state.Active {
		json.NewEncoder(w).Encode(map[string]string{"error": "No interrupted queue found"})
		return
	}
	
	// Resume from where we left off
	remaining := state.Targets[state.CurrentIdx:]
	req := ScanRequest{
		Targets:     remaining,
		Instruction: state.Instruction,
		ScanMode:    state.ScanMode,
	}
	
	// Start resume in background
	go s.runMultiScan(req)
	
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":       "resumed",
		"from_index":   state.CurrentIdx,
		"targets_left":  len(remaining),
	})
}

// handleQueueClear clears an interrupted queue state
func (s *Server) handleQueueClear(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	s.clearQueueState()
	json.NewEncoder(w).Encode(map[string]string{"status": "cleared"})
}

// handleGetScan returns a specific scan's full data.
func (s *Server) handleGetScan(w http.ResponseWriter, r *http.Request) {
	// Extract scan ID from URL: /api/scans/{id}
	scanID := strings.TrimPrefix(r.URL.Path, "/api/scans/")
	if scanID == "" || scanID == "latest" {
		// Find latest scan by modification time
		entries, _ := os.ReadDir(s.dataDir)
		if len(entries) == 0 {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`null`))
			return
		}
		// Sort by mod time, pick most recent
		type dirEntry struct {
			name    string
			modTime time.Time
		}
		var dirs []dirEntry
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			info, err := e.Info()
			if err != nil {
				continue
			}
			dirs = append(dirs, dirEntry{name: e.Name(), modTime: info.ModTime()})
		}
		if len(dirs) == 0 {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`null`))
			return
		}
		sort.Slice(dirs, func(i, j int) bool {
			return dirs[i].modTime.Before(dirs[j].modTime)
		})
		scanID = dirs[len(dirs)-1].name
	}

	// If this is the currently running scan, return live in-memory data
	s.mu.RLock()
	live := s.liveScanRecord
	s.mu.RUnlock()
	if live != nil && live.ID == scanID {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(live)
		return
	}

	scanPath := filepath.Join(s.dataDir, scanID, "scan.json")
	data, err := os.ReadFile(scanPath)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`null`))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(data)
}

func (s *Server) broadcast(evt WSEvent) {
	data, err := json.Marshal(evt)
	if err != nil {
		return
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	for conn := range s.clients {
		conn.WriteMessage(websocket.TextMessage, data)
	}
}

// sendDiscord sends a rich embed message to the configured Discord webhook.
func (s *Server) sendDiscord(color int, title, description string) {
	s.sendDiscordWithFile(color, title, description, "")
}

// sendDiscordWithFile sends a rich embed message with an optional file attachment to Discord.
func (s *Server) sendDiscordWithFile(color int, title, description, filePath string) {
	if s.discordWebhook == "" {
		return
	}

	// If no file, send simple embed
	if filePath == "" {
		s.sendSimpleEmbed(color, title, description)
		return
	}

	// Check if file exists
	fileData, err := os.ReadFile(filePath)
	if err != nil {
		log.Printf("Failed to read PDF for Discord: %v", err)
		// Send embed without file
		s.sendSimpleEmbed(color, title, description+" (PDF generation failed)")
		return
	}

	// Create multipart form data
	var b bytes.Buffer
	writer := multipart.NewWriter(&b)

	// Add payload JSON
	embedPayload := map[string]any{
		"username":   "Xalgorix",
		"avatar_url": "https://raw.githubusercontent.com/xalgord/xalgord/main/assets/logo.png",
		"embeds": []map[string]any{
			{
				"title":       title,
				"description": description,
				"color":       color,
				"timestamp":   time.Now().Format(time.RFC3339),
				"footer": map[string]string{
					"text": "Xalgorix — Autonomous AI Pentesting Engine",
				},
			},
		},
	}
	embedJSON, _ := json.Marshal(embedPayload)
	writer.WriteField("payload_json", string(embedJSON))

	// Add file
	part, _ := writer.CreateFormFile("file", filepath.Base(filePath))
	part.Write(fileData)
	writer.Close()

	// Send request
	go func() {
		client := &http.Client{Timeout: 30 * time.Second}
		resp, err := client.Post(s.discordWebhook, writer.FormDataContentType(), &b)
		if err != nil {
			log.Printf("Discord webhook file upload error: %v", err)
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 && resp.StatusCode != 204 {
			body, _ := io.ReadAll(resp.Body)
			log.Printf("Discord webhook error: %d %s", resp.StatusCode, string(body))
		}
	}()
}

// sendSimpleEmbed sends a simple embed without file attachment
func (s *Server) sendSimpleEmbed(color int, title, description string) {
	payload := map[string]any{
		"username":   "Xalgorix",
		"avatar_url": "https://raw.githubusercontent.com/xalgord/xalgord/main/assets/logo.png",
		"embeds": []map[string]any{
			{
				"title":       title,
				"description": description,
				"color":       color,
				"timestamp":   time.Now().Format(time.RFC3339),
				"footer": map[string]string{
					"text": "Xalgorix — Autonomous AI Pentesting Engine",
				},
			},
		},
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return
	}

	go func() {
		resp, err := http.Post(s.discordWebhook, "application/json", bytes.NewReader(body))
		if err != nil {
			log.Printf("Discord webhook error: %v", err)
			return
		}
		resp.Body.Close()
	}()
}
