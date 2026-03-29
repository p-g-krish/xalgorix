// Package web provides the Xalgorix web UI server.
package web

import (
	"bufio"
	"bytes"
	"context"
	cryptorand "crypto/rand"
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"log"
	"mime/multipart"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
	"github.com/xalgord/xalgorix/internal/agent"
	"github.com/xalgord/xalgorix/internal/config"
	"github.com/xalgord/xalgorix/internal/tools/notes"
	"github.com/xalgord/xalgorix/internal/tools/reporting"
	"github.com/xalgord/xalgorix/internal/tools/terminal"
)

const version = "3.10.0"

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
			if r.URL.Path == "/ws" || strings.HasPrefix(r.URL.Path, "/static") || strings.HasPrefix(r.URL.Path, "/assets") {
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
	Type            string            `json:"type"`
	Content         string            `json:"content,omitempty"`
	ToolName        string            `json:"tool_name,omitempty"`
	ToolArgs        map[string]string `json:"tool_args,omitempty"`
	Output          string            `json:"output,omitempty"`
	Error           string            `json:"error,omitempty"`
	AgentID         string            `json:"agent_id,omitempty"`
	Timestamp       string            `json:"timestamp,omitempty"`
	Vulns           []VulnSummary     `json:"vulns,omitempty"`
	TargetIndex     int               `json:"target_index,omitempty"`
	TotalTargets    int               `json:"total_targets,omitempty"`
	Target          string            `json:"target,omitempty"`
	TotalTokens     int               `json:"total_tokens,omitempty"`
	SubTargetIndex  int               `json:"sub_target_index,omitempty"`  // subdomain index within a wildcard target
	SubTargetTotal  int               `json:"sub_target_total,omitempty"`  // total subdomains for current wildcard target
	ParentTarget    string            `json:"parent_target,omitempty"`     // parent domain for subdomain scans
}

// VulnSummary is a simplified vulnerability for the UI.
type VulnSummary struct {
	ID                 string  `json:"id"`
	Title              string  `json:"title"`
	Severity           string  `json:"severity"`
	Endpoint           string  `json:"endpoint"`
	CVSS               float64 `json:"cvss"`
	Description        string  `json:"description,omitempty"`
	Impact             string  `json:"impact,omitempty"`
	Method             string  `json:"method,omitempty"`
	CVE                string  `json:"cve,omitempty"`
	TechnicalAnalysis  string  `json:"technical_analysis,omitempty"`
	PoCDescription     string  `json:"poc_description,omitempty"`
	PoCScript          string  `json:"poc_script,omitempty"`
	Remediation        string  `json:"remediation,omitempty"`
	ExploitationProof  string  `json:"exploitation_proof,omitempty"`
	VerificationMethod string  `json:"verification_method,omitempty"`
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
	currentAgent   *agent.Agent     // current agent for chat support
	cancelScan     context.CancelFunc // cancels the current scan session context
	running        atomic.Bool
	stopReq        atomic.Bool
	dataDir        string
	currentScanDir string
	currentScanID  string
	discordWebhook string
	rateLimiter    *RateLimiter
}

// NewServer creates a new web server.
func NewServer(cfg *config.Config, port int) *Server {
	home, _ := os.UserHomeDir()
	dataDir := filepath.Join(home, "xalgorix-data")
	// Rate limit from config (defaults: 60 requests per minute)
	rl := NewRateLimiter(cfg.RateLimitRequests, time.Duration(cfg.RateLimitWindow)*time.Second)
	
	return &Server{
		cfg:            cfg,
		port:           port,
		clients:        make(map[*websocket.Conn]bool),
		dataDir:        dataDir,
		discordWebhook: os.Getenv("XALGORIX_DISCORD_WEBHOOK"),
		rateLimiter:    rl,
	}
}

// Start launches the web server.
func (s *Server) Start() error {
	s.initDataDir()

	// Auto-start Caido proxy in background if available
	startCaidoProxy()

	staticFS, err := fs.Sub(staticFiles, "static")
	if err != nil {
		return fmt.Errorf("failed to load static files: %w", err)
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
		// Check if it's a real static file - strip /static prefix since staticFS already points to static folder
		strippedPath := strings.TrimPrefix(path, "/static/")
		f, err := staticFS.(fs.ReadFileFS).ReadFile(strippedPath)
		if err == nil && f != nil {
			// Rewrite URL to serve from staticFS root (which is already "static")
			r.URL.Path = "/" + strippedPath
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
	mux.HandleFunc("/api/settings/agentmail", s.handleAgentMailSettings)
	mux.HandleFunc("/api/queue/status", s.handleQueueStatus)
	mux.HandleFunc("/api/queue/resume", s.handleQueueResume)
	mux.HandleFunc("/api/queue/clear", s.handleQueueClear)
	mux.HandleFunc("/api/version", s.handleVersion)
	mux.HandleFunc("/api/stop-notify", s.handleStopNotify)

	mux.HandleFunc("/api/chat", s.handleChat)

	// Wrap with rate limiting middleware
	rlMiddleware := rateLimitMiddleware(s.rateLimiter)
	
	addr := fmt.Sprintf("0.0.0.0:%d", s.port)
	log.Printf("Xalgorix Web UI → http://localhost:%d", s.port)
	log.Printf("Scan data → %s", s.dataDir)
	log.Printf("Rate limiting: %d requests/%ds per IP", s.cfg.RateLimitRequests, s.cfg.RateLimitWindow)
	return http.ListenAndServe(addr, rlMiddleware(mux))
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
			// Apply LLM provider settings from WebSocket message securely using a copy
			scanCfg := *s.cfg // shallow copy
			if req.Model != "" {
				scanCfg.LLM = req.Model
			}
			if req.APIKey != "" {
				scanCfg.APIKey = req.APIKey
			}
			if req.APIBase != "" {
				scanCfg.APIBase = req.APIBase
			}
			go s.runMultiScan(req, &scanCfg)
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

	// Apply LLM provider settings from web UI securely using a copy
	scanCfg := *s.cfg // shallow copy
	if req.Model != "" {
		scanCfg.LLM = req.Model
	}
	if req.APIKey != "" {
		scanCfg.APIKey = req.APIKey
	}
	if req.APIBase != "" {
		scanCfg.APIBase = req.APIBase
	}

	go s.runMultiScan(req, &scanCfg)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "started"})
}


func (s *Server) handleStop(w http.ResponseWriter, r *http.Request) {
	s.stopReq.Store(true)

	// Cancel the current scan session context (interrupts LLM calls, tool execution)
	s.mu.Lock()
	cancel := s.cancelScan
	agnt := s.currentAgent
	s.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if agnt != nil {
		agnt.Stop()
	}
	// Kill all spawned processes as a safety net
	terminal.KillAllProcesses()

	// Do NOT set s.running = false here — let the runMultiScan goroutine
	// handle its own cleanup to avoid a race where a new scan starts
	// before the old goroutine has fully exited.
	s.broadcast(WSEvent{Type: "stopped", Content: "Agent stopped by user"})
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "stopped"})
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	s.mu.RLock()
	scanID := s.currentScanID
	s.mu.RUnlock()
	json.NewEncoder(w).Encode(map[string]any{
		"running": s.running.Load(),
		"scan_id": scanID,
		"vulns":   len(reporting.GetVulnerabilities()),
	})
}

// ────────────────────────────────────────────────────────
// scanSession — self-contained unit for a single scan run
// ────────────────────────────────────────────────────────

// scanSession isolates all per-scan state. Crashes in one session
// cannot corrupt server-level state or leak into subsequent scans.
type scanSession struct {
	id             string
	target         string
	scanDir        string
	cfg            *config.Config
	agent          *agent.Agent
	events         chan agent.Event
	record         *ScanRecord
	server         *Server
	instruction    string
	severityFilter []string
	discoveryMode  bool
	genReport      bool
	resetState     bool
}

// cleanup tears down all per-session resources. Every sub-operation
// has its own panic guard so cleanup NEVER panics upward.
func (sess *scanSession) cleanup() {
	// Kill all processes spawned during this session
	func() {
		defer func() { recover() }()
		terminal.KillAllProcesses()
	}()

	// Stop agent if still running
	if sess.agent != nil {
		func() {
			defer func() { recover() }()
			sess.agent.Stop()
		}()
	}

	// Clear server references under lock
	sess.server.mu.Lock()
	if sess.server.currentAgent == sess.agent {
		sess.server.currentAgent = nil
	}
	sess.server.mu.Unlock()
}

// executeScanSession runs a single scan in complete isolation.
// It NEVER panics upward — all panics are caught and logged.
func (s *Server) executeScanSession(sess *scanSession) {
	// IRONCLAD: This function NEVER panics upward.
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[CRITICAL] scanSession %s panicked: %v", sess.id, r)
			s.broadcast(WSEvent{Type: "error", Content: fmt.Sprintf("⛔ Scan %s crashed: %v — continuing", sess.target, r)})
		}
		// ALWAYS clean up, whether normal exit or panic
		sess.cleanup()
	}()

	// 1. Reset global state if requested (with its own panic guard)
	if sess.resetState {
		func() {
			defer func() { recover() }()
			reporting.ResetVulnerabilities()
			notes.ResetNotes()
		}()
	}

	// 2. Set working directory
	terminal.SetWorkDir(sess.scanDir)

	// 3. Create agent with session's config
	events := make(chan agent.Event, 512)
	sess.events = events
	agnt := agent.NewAgent(sess.cfg, "XalgorixAgent", events)
	if sess.discoveryMode {
		agnt.SetDiscoveryMode(true)
	}
	sess.agent = agnt

	// Store agent ref on server for handleStop/handleChat (under lock)
	s.mu.Lock()
	s.currentScanDir = sess.scanDir
	s.currentScanID = sess.id
	s.currentAgent = agnt
	s.mu.Unlock()

	// 4. Initialize scan record
	sess.record = &ScanRecord{
		ID:        sess.id,
		Target:    sess.target,
		StartedAt: time.Now().Format(time.RFC3339),
		Status:    "running",
		Events:    []WSEvent{},
		Vulns:     []VulnSummary{},
	}
	s.saveScanRecordTo(sess.record, sess.scanDir)

	// 5. Event processing goroutine — drains events and broadcasts to WebSocket
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer func() { recover() }() // never panic in event processor
		for evt := range events {
			s.processEvent(evt, sess)
		}
	}()

	// 6. Build instruction with severity filter
	instruction := sess.instruction
	if len(sess.severityFilter) > 0 {
		instruction = buildSeverityPrefix(sess.severityFilter) + "\n\n" + instruction
	}

	// 7. Run agent (blocks until finished or stopped)
	agnt.Run([]string{sess.target}, instruction)

	// 8. Close events channel and wait for event processor to drain
	close(events)
	<-done

	// 9. Finalize record
	sess.record.Status = "finished"
	sess.record.FinishedAt = time.Now().Format(time.RFC3339)

	// Refresh vulns from reporting module
	sess.record.Vulns = nil
	for _, v := range reporting.GetVulnerabilities() {
		sess.record.Vulns = append(sess.record.Vulns, vulnToSummary(v))
	}

	s.saveScanRecordTo(sess.record, sess.scanDir)

	// 10. Generate report if requested
	if sess.genReport && len(sess.record.Vulns) > 0 {
		if p, err := s.generateReportAt(sess.record, sess.scanDir); err == nil {
			log.Printf("PDF report saved: %s", p)
			desc := fmt.Sprintf("**Target:** %s\n**Vulnerabilities:** %d found\n**Completed at:** %s",
				sess.target, len(sess.record.Vulns), time.Now().Format("15:04:05 MST"))
			s.sendDiscordWithFile(0x3b82f6, "✅ Scan Finished - Report Ready", desc, p)
			s.broadcast(WSEvent{Type: "report_ready", Content: fmt.Sprintf("/api/report/%s", sess.id)})
		} else {
			log.Printf("Failed to generate PDF report: %v", err)
		}
	}
}

// processEvent handles a single agent event — forwards to WebSocket, updates scan record, sends Discord.
func (s *Server) processEvent(evt agent.Event, sess *scanSession) {
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
				sess.record.Vulns = append(sess.record.Vulns, vs)

				// Discord: vulnerability found
				sevColor := 0xef4444 // red for critical/high
				switch vs.Severity {
				case "medium":
					sevColor = 0xd97706
				case "low", "info":
					sevColor = 0x3b82f6
				}
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
		sess.record.Iterations++
	}
	if evt.Type == "tool_call" {
		sess.record.ToolCalls++
	}
	if evt.TotalTokens > 0 {
		sess.record.TotalTokens = evt.TotalTokens
	}

	// Accumulate events for persistence (limit stored output size)
	savedEvt := wsEvt
	if len(savedEvt.Output) > 500 {
		savedEvt.Output = savedEvt.Output[:500] + "..."
	}
	sess.record.Events = append(sess.record.Events, savedEvt)

	// Periodically save scan record (every 10 events)
	if len(sess.record.Events)%10 == 0 {
		s.saveScanRecordTo(sess.record, sess.scanDir)
	}

	s.broadcast(wsEvt)
}

// buildSeverityPrefix creates the severity filter instruction prefix.
func buildSeverityPrefix(severityFilter []string) string {
	severityText := "CRITICAL INSTRUCTION: You MUST ONLY look for and report "
	severities := make([]string, len(severityFilter))
	copy(severities, severityFilter)
	severityText += strings.Join(severities, " and ") + " severity vulnerabilities. "
	severityText += "DO NOT report, investigate, or mention any LOW severity, INFORMATIONAL, or INFO findings. "
	severityText += "Ignore any potential LOW/INFO issues - they are out of scope for this engagement. "
	severityText += "Focus ONLY on: " + strings.Join(severities, ", ") + "."
	return severityText
}

// ────────────────────────────────────────────────────────
// runMultiScan — orchestrates scanning across all targets
// ────────────────────────────────────────────────────────

// runMultiScan processes targets sequentially, one at a time.
// Each target is scanned in a fully isolated scanSession.
func (s *Server) runMultiScan(req ScanRequest, scanCfg *config.Config) {
	if s.running.Load() {
		s.broadcast(WSEvent{Type: "error", Content: "A scan is already running"})
		return
	}

	// Top-level panic recovery — if ANYTHING in this goroutine panics,
	// we MUST clean up and mark the scan as finished.
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[CRITICAL] runMultiScan goroutine panicked: %v", r)
			s.broadcast(WSEvent{Type: "error", Content: fmt.Sprintf("⛔ Scan goroutine crashed: %v — cleaning up", r)})
		}
		// ALWAYS clean up, whether we finished normally or crashed
		s.clearQueueState()
		s.mu.Lock()
		s.cancelScan = nil
		s.currentAgent = nil
		s.mu.Unlock()
		s.broadcast(WSEvent{Type: "queue_finished", Content: "Scan queue ended"})
		time.Sleep(500 * time.Millisecond)
		s.running.Store(false)
		log.Printf("[INFO] runMultiScan goroutine exited, s.running=false")
	}()

	// Clear any previous queue state
	s.clearQueueState()
	s.running.Store(true)
	s.stopReq.Store(false)
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
		if s.stopReq.Load() {
			s.broadcast(WSEvent{Type: "stopped", Content: "Scan queue stopped by user"})
			break
		}

		// Update queue state after each target
		s.saveQueueState(req.Targets, i, req.Instruction, req.ScanMode)

		// Per-target context with 2-hour timeout
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Hour)
		s.mu.Lock()
		s.cancelScan = cancel
		s.mu.Unlock()

		switch req.ScanMode {
		case "wildcard":
			s.runWildcardTarget(ctx, scanCfg, req, target, i, totalTargets)
		case "dast":
			s.runDASTTarget(ctx, scanCfg, req, target, i, totalTargets)
		default:
			s.runSingleTarget(ctx, scanCfg, req, target, i, totalTargets)
		}

		cancel() // always cancel context after target is done
	}

	// Clear queue state when done
	s.clearQueueState()

	// Discord: scan finished
	vulns := reporting.GetVulnerabilities()
	if len(vulns) > 0 {
		desc := fmt.Sprintf("**Targets:** %d completed\n**Vulnerabilities:** %d found\n**Completed at:** %s", totalTargets, len(vulns), time.Now().Format("15:04:05 MST"))
		s.sendDiscord(0x3b82f6, "✅ Scan Finished - Vulnerabilities Found", desc)
	} else {
		s.sendDiscord(0x3b82f6, "✅ Scan Finished", fmt.Sprintf("**Targets:** %d completed\n**Vulnerabilities:** 0 found\n**Completed at:** %s", totalTargets, time.Now().Format("15:04:05 MST")))
	}

	log.Printf("[INFO] runMultiScan main body complete")
}

// ────────────────────────────────────────────────────────
// Mode-specific target handlers
// ────────────────────────────────────────────────────────

// makeScanDir creates a per-target scan directory with nested structure: target/date/randomslug
func (s *Server) makeScanDir(target string) string {
	dateDir := time.Now().Format("2006-01-02")
	scanDirName := fmt.Sprintf("%s_%s", sanitizeTarget(target), randomSlug())
	scanDir := filepath.Join(s.dataDir, target, dateDir, scanDirName)
	os.MkdirAll(scanDir, 0755)
	return scanDir
}

// runSingleTarget handles a single-site mode scan for one target.
func (s *Server) runSingleTarget(ctx context.Context, scanCfg *config.Config, req ScanRequest, target string, idx, total int) {
	scanDir := s.makeScanDir(target)

	instruction := "This is a SINGLE TARGET scan. Do NOT enumerate subdomains or perform wildcard discovery. Only test the exact target URL provided. Focus on the main domain/IP only. " + req.Instruction

	s.broadcast(WSEvent{
		Type:         "target_started",
		Content:      fmt.Sprintf("Scanning target %d/%d: %s", idx+1, total, target),
		Target:       target,
		AgentID:      filepath.Base(scanDir),
		TargetIndex:  idx + 1,
		TotalTargets: total,
	})

	sess := &scanSession{
		id:             filepath.Base(scanDir),
		target:         target,
		scanDir:        scanDir,
		cfg:            scanCfg,
		server:         s,
		instruction:    buildAutonomousInstruction(target, instruction),
		severityFilter: req.SeverityFilter,
		discoveryMode:  false,
		genReport:      true,
		resetState:     true,
	}
	s.executeScanSession(sess)

	s.broadcast(WSEvent{
		Type:         "target_completed",
		Content:      fmt.Sprintf("Target %d/%d completed: %s", idx+1, total, target),
		Target:       target,
		TargetIndex:  idx + 1,
		TotalTargets: total,
	})
}

// runDASTTarget handles a DAST mode scan for one target URL.
func (s *Server) runDASTTarget(ctx context.Context, scanCfg *config.Config, req ScanRequest, target string, idx, total int) {
	scanDir := s.makeScanDir(target)

	dastInstruction := buildDASTInstruction(target)
	if req.Instruction != "" {
		dastInstruction += "\n\n" + req.Instruction
	}

	s.broadcast(WSEvent{
		Type:         "target_started",
		Content:      fmt.Sprintf("[DAST] Scanning URL: %s", target),
		Target:       target,
		AgentID:      filepath.Base(scanDir),
		TargetIndex:  idx + 1,
		TotalTargets: total,
	})

	sess := &scanSession{
		id:             filepath.Base(scanDir),
		target:         target,
		scanDir:        scanDir,
		cfg:            scanCfg,
		server:         s,
		instruction:    dastInstruction,
		severityFilter: req.SeverityFilter,
		discoveryMode:  false,
		genReport:      true,
		resetState:     true,
	}
	s.executeScanSession(sess)

	s.broadcast(WSEvent{
		Type:         "target_completed",
		Content:      fmt.Sprintf("[DAST] Completed: %s", target),
		Target:       target,
		TargetIndex:  idx + 1,
		TotalTargets: total,
	})
}

// runWildcardTarget handles wildcard mode: Phase 1 subdomain discovery, then Phase 2 per-subdomain scanning.
func (s *Server) runWildcardTarget(ctx context.Context, scanCfg *config.Config, req ScanRequest, target string, idx, total int) {
	// ── PHASE 1: Subdomain Discovery ──
	scanDir := s.makeScanDir(target)

	discoveryInstruction := buildDiscoveryInstruction(target)
	if req.Instruction != "" {
		discoveryInstruction += "\n\n" + req.Instruction
	}

	s.broadcast(WSEvent{
		Type:         "target_started",
		Content:      fmt.Sprintf("[PHASE 1] Discovering subdomains for: %s", target),
		Target:       target,
		AgentID:      filepath.Base(scanDir),
		TargetIndex:  idx + 1,
		TotalTargets: total,
	})

	discoverySess := &scanSession{
		id:             filepath.Base(scanDir),
		target:         target,
		scanDir:        scanDir,
		cfg:            scanCfg,
		server:         s,
		instruction:    discoveryInstruction,
		severityFilter: req.SeverityFilter,
		discoveryMode:  true,
		genReport:      false,
		resetState:     false, // don't reset — accumulate vulns across subdomains
	}
	s.executeScanSession(discoverySess)

	// Read discovered subdomains from file
	subdomains := s.collectSubdomains(scanDir, target)

	log.Printf("[INFO] Total subdomains found for %s: %d", target, len(subdomains))

	s.broadcast(WSEvent{
		Type:         "target_completed",
		Content:      fmt.Sprintf("[PHASE 1] Discovery complete: found %d subdomains. Now scanning each individually.", len(subdomains)),
		Target:       target,
		TargetIndex:  idx + 1,
		TotalTargets: total,
	})

	// ── PHASE 2: Scan each subdomain individually ──
	for j, subdomain := range subdomains {
		if s.stopReq.Load() {
			log.Printf("[INFO] Subdomain loop stopped by user at %d/%d for %s", j+1, len(subdomains), target)
			s.broadcast(WSEvent{Type: "stopped", Content: "Scan queue stopped by user"})
			break
		}

		log.Printf("[INFO] Starting subdomain %d/%d: %s (parent: %s)", j+1, len(subdomains), subdomain, target)

		// Each subdomain gets its own isolated session wrapped in a panic guard
		func() {
			defer func() {
				if r := recover(); r != nil {
					log.Printf("[PANIC] Subdomain %d/%d crashed (%s): %v — skipping to next", j+1, len(subdomains), subdomain, r)
					s.broadcast(WSEvent{Type: "error", Content: fmt.Sprintf("⚠️ Subdomain %s crashed: %v — skipping", subdomain, r)})
				}
			}()

			subScanDir := s.makeScanDir(subdomain)
			scanInstruction := buildSubdomainScanInstruction(subdomain, target, req.Instruction)

			s.broadcast(WSEvent{
				Type:           "target_started",
				Content:        fmt.Sprintf("[PHASE 2] Scanning subdomain %d/%d: %s", j+1, len(subdomains), subdomain),
				Target:         subdomain,
				AgentID:        filepath.Base(subScanDir),
				TargetIndex:    idx + 1,
				TotalTargets:   total,
				SubTargetIndex: j + 1,
				SubTargetTotal: len(subdomains),
				ParentTarget:   target,
			})

			// Track vulns BEFORE this subdomain scan to only count new ones
			vulnCountBefore := len(reporting.GetVulnerabilities())

			subSess := &scanSession{
				id:             filepath.Base(subScanDir),
				target:         subdomain,
				scanDir:        subScanDir,
				cfg:            scanCfg,
				server:         s,
				instruction:    scanInstruction,
				severityFilter: req.SeverityFilter,
				discoveryMode:  false,
				genReport:      false,
				resetState:     false, // accumulate vulns across subdomains
			}
			s.executeScanSession(subSess)

			// Generate PDF for this subdomain if NEW vulnerabilities found
			allVulns := reporting.GetVulnerabilities()
			if vulnCountBefore <= len(allVulns) {
				newVulns := allVulns[vulnCountBefore:]
				if len(newVulns) > 0 {
					subScanRecord := ScanRecord{
						ID:         filepath.Base(subScanDir),
						Target:     subdomain,
						StartedAt:  time.Now().Format(time.RFC3339),
						Status:     "finished",
						FinishedAt: time.Now().Format(time.RFC3339),
						Vulns:      []VulnSummary{},
					}
					for _, v := range newVulns {
						subScanRecord.Vulns = append(subScanRecord.Vulns, vulnToSummary(v))
					}
					reportPath, err := s.generateReportAt(&subScanRecord, subScanDir)
					if err == nil {
						desc := fmt.Sprintf("**Target:** %s\n**Vulnerabilities:** %d found", subdomain, len(newVulns))
						s.sendDiscordWithFile(0x3b82f6, "🔴 Vulnerability Found - Report Ready", desc, reportPath)
					}
				}
			}

			s.broadcast(WSEvent{
				Type:           "target_completed",
				Content:        fmt.Sprintf("[PHASE 2] Subdomain %d/%d completed: %s", j+1, len(subdomains), subdomain),
				Target:         subdomain,
				TargetIndex:    idx + 1,
				TotalTargets:   total,
				SubTargetIndex: j + 1,
				SubTargetTotal: len(subdomains),
				ParentTarget:   target,
			})
		}()
	}

	log.Printf("[INFO] Wildcard scan complete for %s: scanned %d subdomains", target, len(subdomains))
	// Clean up processes before next target
	terminal.KillAllProcesses()
}

// buildDiscoveryInstruction creates the Phase 1 subdomain enumeration instruction.
func buildDiscoveryInstruction(target string) string {
	instruction := `# PHASE 1: SUBDOMAIN ENUMERATION ONLY

## YOUR TASK: Find ALL subdomains of TARGET — NOTHING ELSE.

## STRICT RULES:
- You are ONLY allowed to enumerate subdomains in this phase.
- DO NOT run any vulnerability scanners (nuclei, sqlmap, ffuf, gobuster, nikto, etc.).
- DO NOT test for XSS, SQLi, SSRF, IDOR, or any other vulnerability.
- DO NOT analyze JavaScript files, test authentication, or probe endpoints.
- After collecting subdomains, you MUST call finish IMMEDIATELY.

## SAVE ALL FILES IN THE CURRENT DIRECTORY
Save all output files directly in the current working directory (not subdirectories).

## SUBDOMAIN ENUMERATION COMMANDS - RUN ALL:

# 1. subfinder (passive)
subfinder -d TARGET -recursive -silent -o ./passive_subfinder.txt
subfinder -d TARGET -all -recursive -silent -o ./passive_subfinder2.txt

# 2. Certificate Transparency (curl)
curl -s "https://crt.sh/?q=%.TARGET&output=json" | jq -r '.[].name_value' 2>/dev/null | sort -u > ./passive_crt.txt

# 3. findomain
findomain -t TARGET --output ./passive_findomain.txt 2>/dev/null || true

# 4. assetfinder
assetfinder --subs-only TARGET | tee ./passive_assetfinder.txt 2>/dev/null || true

# 5. DNS Bufferover
curl -s "https://dns.bufferover.run/dns?q=.TARGET" | jq -r '.FDNS_A[]' 2>/dev/null | cut -d',' -f2 | sort -u > ./passive_dnsbufferover.txt
curl -s "https://dns.bufferover.run/dns?q=.TARGET" | jq -r '.RDNS[]' 2>/dev/null | cut -d',' -f1 | sort -u >> ./passive_dnsbufferover.txt

# 6. Wayback Machine
curl -s "https://web.archive.org/cdx/search/cdx?url=*.TARGET/*&output=json&fl=original&filter=statuscode:200" | jq -r '.[].original' 2>/dev/null | cut -d'/' -f3 | sort -u > ./archive_subdomains.txt

# 7. Active enumeration
subfinder -d TARGET -all -recursive -t 100 -o ./active_subfinder.txt

# 8. MERGE ALL RESULTS
cat ./passive_*.txt ./active_*.txt ./archive_subdomains.txt 2>/dev/null | grep -v '*' | grep -v '@' | sort -u > ./all_subdomains.txt
echo "Total unique subdomains found:"
wc -l ./all_subdomains.txt

# 9. RESOLVE TO FIND LIVE HOSTS
cat ./all_subdomains.txt | dnsx -silent -a -resp -threads 100 -o ./live_resolved.txt 2>/dev/null || true
cat ./live_resolved.txt | cut -d' ' -f1 | grep -v '^$' | sort -u > ./live_subdomains.txt
echo "Live subdomains:"
wc -l ./live_subdomains.txt

## FINAL STEP (MANDATORY):
1. Call add_note with the complete list of live subdomains from ./live_subdomains.txt
2. Call finish IMMEDIATELY after. The system will handle vulnerability scanning of each subdomain separately.

DO NOT continue past this point. DO NOT scan for vulnerabilities. Call finish NOW.`

	// Replace TARGET placeholder with actual target
	instruction = strings.ReplaceAll(instruction, "TARGET", target)
	return instruction
}

// collectSubdomains reads discovered subdomains from all known file locations and agent notes.
func (s *Server) collectSubdomains(scanDir, target string) []string {
	seen := make(map[string]bool)
	var subdomains []string

	// Helper: extract valid subdomains from a file
	extractFromFile := func(path string) []string {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		var found []string
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "Total") || strings.HasPrefix(line, "wc") {
				continue
			}
			line = strings.TrimPrefix(line, "http://")
			line = strings.TrimPrefix(line, "https://")
			line = strings.TrimPrefix(line, "http[s]://")
			parts := strings.Fields(line)
			if len(parts) > 0 {
				domain := strings.TrimRight(parts[0], "/.,;:")
				if strings.Contains(domain, ".") && !seen[domain] {
					seen[domain] = true
					found = append(found, domain)
				}
			}
		}
		return found
	}

	// Helper: extract subdomains from a text blob (e.g., agent notes)
	extractFromText := func(text string) []string {
		var found []string
		for _, line := range strings.Split(text, "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			line = strings.TrimPrefix(line, "- ")
			line = strings.TrimPrefix(line, "* ")
			line = strings.TrimPrefix(line, "http://")
			line = strings.TrimPrefix(line, "https://")
			parts := strings.Fields(line)
			if len(parts) > 0 {
				domain := strings.TrimRight(parts[0], "/.,;:")
				if strings.Contains(domain, ".") && strings.Contains(domain, target) && !seen[domain] {
					seen[domain] = true
					found = append(found, domain)
				}
			}
		}
		return found
	}

	subdomainFileNames := []string{
		"live_subdomains.txt", "live_resolved.txt", "all_subdomains.txt",
		"all_discovered_subdomains.txt", "subdomains.txt", "live_hosts.txt",
		"passive_subfinder.txt", "passive_subfinder2.txt", "active_subfinder.txt",
	}

	log.Printf("[DEBUG] Looking for subdomains in: %s", scanDir)

	// Layer 1: Check exact files in scan directory
	for _, name := range subdomainFileNames {
		path := filepath.Join(scanDir, name)
		if found := extractFromFile(path); len(found) > 0 {
			subdomains = append(subdomains, found...)
			log.Printf("[DEBUG] Layer 1: Found %d subdomains in %s", len(found), path)
			if name == "live_subdomains.txt" || name == "live_resolved.txt" {
				break
			}
		}
	}

	// Layer 2: Walk scan directory tree for any matching files
	if len(subdomains) == 0 {
		filepath.WalkDir(scanDir, func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			base := filepath.Base(path)
			for _, name := range subdomainFileNames {
				if base == name {
					if found := extractFromFile(path); len(found) > 0 {
						subdomains = append(subdomains, found...)
						log.Printf("[DEBUG] Layer 2: Found %d subdomains in %s", len(found), path)
						return nil
					}
				}
			}
			return nil
		})
	}

	// Layer 3: Check /tmp/ for subdomain files
	if len(subdomains) == 0 {
		for _, name := range subdomainFileNames {
			path := filepath.Join("/tmp", name)
			if found := extractFromFile(path); len(found) > 0 {
				subdomains = append(subdomains, found...)
				log.Printf("[DEBUG] Layer 3: Found %d subdomains in %s", len(found), path)
				break
			}
		}
		if len(subdomains) == 0 {
			tmpEntries, _ := os.ReadDir("/tmp")
			for _, e := range tmpEntries {
				if e.IsDir() {
					continue
				}
				name := e.Name()
				if (strings.Contains(name, "subdomain") || strings.Contains(name, "live") || strings.Contains(name, target)) && strings.HasSuffix(name, ".txt") {
					path := filepath.Join("/tmp", name)
					if found := extractFromFile(path); len(found) > 0 {
						subdomains = append(subdomains, found...)
						log.Printf("[DEBUG] Layer 3b: Found %d subdomains in %s", len(found), path)
						break
					}
				}
			}
		}
	}

	// Layer 4: Parse agent notes for subdomain data
	if len(subdomains) == 0 {
		allNotes := notes.GetAllNotes()
		for key, value := range allNotes {
			lowerKey := strings.ToLower(key)
			if strings.Contains(lowerKey, "subdomain") || strings.Contains(lowerKey, "live") || strings.Contains(lowerKey, "discovered") || strings.Contains(lowerKey, "domain") {
				if found := extractFromText(value); len(found) > 0 {
					subdomains = append(subdomains, found...)
					log.Printf("[DEBUG] Layer 4: Found %d subdomains in note '%s'", len(found), key)
				}
			}
		}
		if len(subdomains) == 0 {
			for _, value := range allNotes {
				if found := extractFromText(value); len(found) > 0 {
					subdomains = append(subdomains, found...)
				}
			}
			if len(subdomains) > 0 {
				log.Printf("[DEBUG] Layer 4b: Extracted %d subdomains from general notes", len(subdomains))
			}
		}
	}

	if len(subdomains) == 0 {
		log.Printf("[WARN] No subdomains found after all 4 fallback layers for target: %s", target)
	}

	return subdomains
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

// saveScanRecordTo saves a scan record to a specific directory.
func (s *Server) saveScanRecordTo(rec *ScanRecord, scanDir string) {
	if scanDir == "" {
		return
	}
	data, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return
	}
	os.WriteFile(filepath.Join(scanDir, "scan.json"), data, 0644)
}

// saveScanRecord saves a scan record to the current scan directory (backward compat).
func (s *Server) saveScanRecord(rec *ScanRecord) {
	s.mu.RLock()
	dir := s.currentScanDir
	s.mu.RUnlock()
	s.saveScanRecordTo(rec, dir)
}

// vulnToSummary converts a reporting.Vulnerability to a VulnSummary with all fields.
func vulnToSummary(v reporting.Vulnerability) VulnSummary {
	return VulnSummary{
		ID:                 v.ID,
		Title:              v.Title,
		Severity:           v.Severity,
		Endpoint:           v.Endpoint,
		CVSS:               v.CVSS,
		Description:        v.Description,
		Impact:             v.Impact,
		Method:             v.Method,
		CVE:                v.CVE,
		TechnicalAnalysis:  v.TechnicalAnalysis,
		PoCDescription:     v.PoCDescription,
		PoCScript:          v.PoCScript,
		Remediation:        v.Remediation,
		ExploitationProof:  v.ExploitationProof,
		VerificationMethod: v.VerificationMethod,
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

// generateReportAt generates a PDF report, saving it to a specific directory.
func (s *Server) generateReportAt(scan *ScanRecord, scanDir string) (string, error) {
	// Temporarily set currentScanDir for the report generator,
	// then restore it. The report.go generateReport method reads s.currentScanDir.
	s.mu.Lock()
	prevDir := s.currentScanDir
	s.currentScanDir = scanDir
	s.mu.Unlock()

	reportPath, err := s.generateReport(scan)

	s.mu.Lock()
	s.currentScanDir = prevDir
	s.mu.Unlock()

	return reportPath, err
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

// handleAgentMailSettings handles GET and POST for AgentMail settings.
func (s *Server) handleAgentMailSettings(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	
	switch r.Method {
	case "GET":
		// Return current AgentMail settings (without exposing the full API key)
		apiKey := s.cfg.AgentMailAPIKey
		masked := ""
		if len(apiKey) > 8 {
			masked = "****" + apiKey[len(apiKey)-8:]
		} else if apiKey != "" {
			masked = "****"
		}
		json.NewEncoder(w).Encode(map[string]string{
			"pod":     s.cfg.AgentMailPod,
			"apiKey":  masked,
		})
		
	case "POST":
		// Update AgentMail settings
		var req struct {
			Pod    string `json:"pod"`
			APIKey string `json:"apiKey"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		
		// Update config
		s.cfg.AgentMailPod = req.Pod
		s.cfg.AgentMailAPIKey = req.APIKey
		
		// Save to env file — read existing content and update only relevant keys
		home, _ := os.UserHomeDir()
		envFile := filepath.Join(home, ".xalgorix.env")
		
		existing, _ := os.ReadFile(envFile)
		lines := strings.Split(string(existing), "\n")
		var newLines []string
		podSet, keySet := false, false
		for _, line := range lines {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "AGENTMAIL_POD=") {
				newLines = append(newLines, "AGENTMAIL_POD="+req.Pod)
				podSet = true
			} else if strings.HasPrefix(trimmed, "AGENTMAIL_API_KEY=") {
				newLines = append(newLines, "AGENTMAIL_API_KEY="+req.APIKey)
				keySet = true
			} else {
				newLines = append(newLines, line)
			}
		}
		if !podSet {
			newLines = append(newLines, "AGENTMAIL_POD="+req.Pod)
		}
		if !keySet {
			newLines = append(newLines, "AGENTMAIL_API_KEY="+req.APIKey)
		}
		
		if err := os.WriteFile(envFile, []byte(strings.Join(newLines, "\n")), 0600); err != nil {
			log.Printf("Failed to save AgentMail settings: %v", err)
		}
		
		log.Printf("AgentMail settings updated: pod=%s", req.Pod)
		
		// Safe masking — handle short API keys
		maskedKey := "****"
		if len(req.APIKey) > 8 {
			maskedKey = "****" + req.APIKey[len(req.APIKey)-8:]
		}
		json.NewEncoder(w).Encode(map[string]string{
			"pod":    req.Pod,
			"apiKey": maskedKey,
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
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "message is required"})
		return
	}

	// Check if there's an active scan
	s.mu.RLock()
	agnt := s.currentAgent
	s.mu.RUnlock()
	if agnt == nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "no active scan"})
		return
	}

	// Send the message to the agent
	response, err := agnt.SendMessage(req.Message)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
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
	
	if s.running.Load() {
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
	scanCfg := *s.cfg
	go s.runMultiScan(req, &scanCfg)
	
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

	// Note: live scan data is now managed per-session, not stored on Server.
	// For active scans, data is written to disk periodically by the session.

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

	// Copy client set under lock, then write outside the lock
	s.mu.RLock()
	clients := make(map[*websocket.Conn]bool, len(s.clients))
	for conn := range s.clients {
		clients[conn] = true
	}
	s.mu.RUnlock()

	for conn := range clients {
		conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		if err := conn.WriteMessage(websocket.TextMessage, data); err != nil {
			log.Printf("WebSocket write error, removing client: %v", err)
			s.mu.Lock()
			delete(s.clients, conn)
			s.mu.Unlock()
			conn.Close()
		}
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

	// Capture content type before goroutine to avoid fragile writer capture
	contentType := writer.FormDataContentType()

	// Send request
	go func() {
		client := &http.Client{Timeout: 30 * time.Second}
		resp, err := client.Post(s.discordWebhook, contentType, &b)
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

// Serve assets from assets folder
func (s *Server) serveAssets(w http.ResponseWriter, r *http.Request) {
	// Get the file path from the URL
	path := r.URL.Path
	path = strings.TrimPrefix(path, "/assets/")
	
	// Sanitize path to prevent directory traversal
	path = filepath.Clean(path)
	if strings.Contains(path, "..") || filepath.IsAbs(path) {
		http.NotFound(w, r)
		return
	}
	
	// Read from assets folder
	home, _ := os.UserHomeDir()
	assetDir := filepath.Join(home, "xalgorix", "assets")
	assetPath := filepath.Join(assetDir, path)
	
	// Verify the resolved path is still within the asset directory
	absAssetPath, _ := filepath.Abs(assetPath)
	absAssetDir, _ := filepath.Abs(assetDir)
	if !strings.HasPrefix(absAssetPath, absAssetDir+string(os.PathSeparator)) {
		http.NotFound(w, r)
		return
	}
	
	// Also check local assets folder
	localAssetDir := filepath.Join(filepath.Dir(os.Args[0]), "..", "assets")
	localAssetPath := filepath.Join(localAssetDir, path)
	
	var data []byte
	var err error
	
	// Try local path first (with path validation)
	absLocalPath, _ := filepath.Abs(localAssetPath)
	absLocalDir, _ := filepath.Abs(localAssetDir)
	if strings.HasPrefix(absLocalPath, absLocalDir+string(os.PathSeparator)) {
		data, err = os.ReadFile(localAssetPath)
	}
	if err != nil {
		// Try xalgorix/assets path
		data, err = os.ReadFile(assetPath)
	}
	
	if err != nil {
		http.NotFound(w, r)
		return
	}
	
	// Set content type based on extension
	if strings.HasSuffix(path, ".png") {
		w.Header().Set("Content-Type", "image/png")
	} else if strings.HasSuffix(path, ".jpg") || strings.HasSuffix(path, ".jpeg") {
		w.Header().Set("Content-Type", "image/jpeg")
	} else if strings.HasSuffix(path, ".svg") {
		w.Header().Set("Content-Type", "image/svg+xml")
	}
	
	w.Write(data)
}

// startCaidoProxy launches Caido proxy in background if it's installed and not already running.
func startCaidoProxy() {
	cfg := config.Get()
	port := cfg.CaidoPort
	if port == 0 {
		port = 8080
	}

	// Check if something is already listening on the Caido port
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 1*time.Second)
	if err == nil {
		conn.Close()
		log.Printf("Caido proxy already running on port %d", port)
		return
	}

	// Check if caido binary exists
	caidoPath, err := exec.LookPath("caido")
	if err != nil {
		log.Printf("Caido not installed — proxy features will use direct HTTP (install from https://caido.io)")
		return
	}

	// Start Caido in background with --no-open (headless)
	cmd := exec.Command(caidoPath, "--no-open", "--listen", fmt.Sprintf("127.0.0.1:%d", port))
	cmd.Stdout = nil
	cmd.Stderr = nil

	if err := cmd.Start(); err != nil {
		log.Printf("⚠️  Failed to start Caido proxy: %v", err)
		return
	}

	// Don't wait for the process — let it run in background
	go func() {
		cmd.Wait() // Reap zombie process
	}()

	log.Printf("✅ Caido proxy started on port %d (PID: %d)", port, cmd.Process.Pid)
}
