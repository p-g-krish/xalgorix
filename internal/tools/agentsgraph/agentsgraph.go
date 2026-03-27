// Package agentsgraph provides multi-agent delegation tools with async spawning.
package agentsgraph

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/xalgord/xalgorix/internal/tools"
)

const maxConcurrentAgents = 3

// AgentRunner is a function that runs a sub-agent. This breaks the import cycle
// between agent and agentsgraph. The agent package injects this at registration time.
type AgentRunner func(name string, targets []string, task string) (string, error)

// subAgentState tracks an async sub-agent.
type subAgentState struct {
	ID          string
	Name        string
	Task        string
	Targets     []string
	Status      string // "running", "completed", "failed"
	StartedAt   time.Time
	CompletedAt time.Time
	Result      string
	Error       string

	// Partial results accumulated during execution
	partialMu      sync.Mutex
	partialResults []string
}

var (
	runner AgentRunner

	// Async sub-agent tracking
	agentsMu     sync.Mutex
	agentCounter int
	agents       = make(map[string]*subAgentState)

	// Semaphore to limit concurrent sub-agents
	agentSemaphore = make(chan struct{}, maxConcurrentAgents)
)

// Register adds multi-agent tools to the registry.
// The agentRunner function is injected to break the import cycle.
func Register(r *tools.Registry, agentRunner AgentRunner) {
	runner = agentRunner

	// Synchronous sub-agent (blocks parent) — kept for backwards compatibility
	r.Register(&tools.Tool{
		Name:        "create_agent",
		Description: "Create and run a sub-agent synchronously (blocks until completion). For long tasks, prefer spawn_agent instead.",
		Parameters: []tools.Parameter{
			{Name: "name", Description: "Name for the sub-agent (e.g. 'SQLi Scanner')", Required: true},
			{Name: "task", Description: "Task description for the sub-agent", Required: true},
			{Name: "target", Description: "Target URL/path for the sub-agent", Required: false},
		},
		Execute: createAgent,
	})

	// Async sub-agent — returns immediately with an agent ID
	r.Register(&tools.Tool{
		Name: "spawn_agent",
		Description: `Launch a sub-agent ASYNCHRONOUSLY. Returns immediately with an agent_id.
Use check_agent to poll for results. Max 3 concurrent sub-agents.
Use this for long-running tasks like port scanning, directory brute-forcing, etc.
The main agent can continue working while sub-agents run in parallel.`,
		Parameters: []tools.Parameter{
			{Name: "name", Description: "Name for the sub-agent (e.g. 'Port Scanner', 'Dir Fuzzer')", Required: true},
			{Name: "task", Description: "Detailed task description — tell the sub-agent exactly what to do", Required: true},
			{Name: "target", Description: "Target URL/host for the sub-agent", Required: false},
		},
		Execute: spawnAgent,
	})

	// Check sub-agent status + partial results
	r.Register(&tools.Tool{
		Name: "check_agent",
		Description: `Check the status and results of a spawned sub-agent.
Returns: status (running/completed/failed), elapsed time, and partial/final results.
Call this periodically to get progress from long-running sub-agents.`,
		Parameters: []tools.Parameter{
			{Name: "agent_id", Description: "The agent_id returned by spawn_agent", Required: true},
		},
		Execute: checkAgent,
	})

	// Wait for sub-agent to complete (blocks)
	r.Register(&tools.Tool{
		Name: "wait_agent",
		Description: `Wait for a spawned sub-agent to complete and return its final results.
This BLOCKS until the sub-agent finishes. Use check_agent if you want to poll instead.`,
		Parameters: []tools.Parameter{
			{Name: "agent_id", Description: "The agent_id returned by spawn_agent", Required: true},
			{Name: "timeout", Description: "Max seconds to wait (default: 600 = 10 min). 0 = wait forever.", Required: false},
		},
		Execute: waitAgent,
	})
}

func createAgent(args map[string]string) (tools.Result, error) {
	name := args["name"]
	task := args["task"]
	target := args["target"]

	if name == "" || task == "" {
		return tools.Result{}, fmt.Errorf("name and task are required")
	}

	targets := []string{}
	if target != "" {
		targets = append(targets, target)
	}

	if runner == nil {
		return tools.Result{}, fmt.Errorf("agent runner not initialized")
	}

	start := time.Now()
	summary, err := runner(name, targets, task)
	elapsed := time.Since(start)

	if err != nil {
		return tools.Result{
			Output: fmt.Sprintf("Sub-agent '%s' failed after %s: %s", name, elapsed.Round(time.Second), err.Error()),
		}, nil
	}

	var b strings.Builder
	b.WriteString(fmt.Sprintf("Sub-agent '%s' completed in %s\n", name, elapsed.Round(time.Second)))
	b.WriteString(summary)

	return tools.Result{
		Output: b.String(),
		Metadata: map[string]any{
			"agent_name": name,
			"elapsed":    elapsed.Seconds(),
		},
	}, nil
}

// spawnAgent launches a sub-agent asynchronously and returns immediately.
func spawnAgent(args map[string]string) (tools.Result, error) {
	name := args["name"]
	task := args["task"]
	target := args["target"]

	if name == "" || task == "" {
		return tools.Result{}, fmt.Errorf("name and task are required")
	}

	if runner == nil {
		return tools.Result{}, fmt.Errorf("agent runner not initialized")
	}

	targets := []string{}
	if target != "" {
		targets = append(targets, target)
	}

	// Check concurrent limit
	agentsMu.Lock()
	runningCount := 0
	for _, a := range agents {
		if a.Status == "running" {
			runningCount++
		}
	}
	agentsMu.Unlock()

	if runningCount >= maxConcurrentAgents {
		return tools.Result{
			Output: fmt.Sprintf("❌ Cannot spawn agent: %d/%d sub-agents already running. Wait for one to finish or use check_agent/wait_agent first.\nRunning agents:\n%s",
				runningCount, maxConcurrentAgents, listRunningAgents()),
		}, nil
	}

	// Create agent state
	agentsMu.Lock()
	agentCounter++
	agentID := fmt.Sprintf("sub_%d_%d", agentCounter, time.Now().Unix())
	state := &subAgentState{
		ID:        agentID,
		Name:      name,
		Task:      task,
		Targets:   targets,
		Status:    "running",
		StartedAt: time.Now(),
	}
	agents[agentID] = state
	agentsMu.Unlock()

	// Launch in background goroutine
	go func() {
		// Acquire semaphore slot
		agentSemaphore <- struct{}{}
		defer func() { <-agentSemaphore }()

		summary, err := runner(name, targets, task)

		agentsMu.Lock()
		defer agentsMu.Unlock()

		state.CompletedAt = time.Now()
		if err != nil {
			state.Status = "failed"
			state.Error = err.Error()
			state.Result = fmt.Sprintf("Sub-agent '%s' failed: %s", name, err.Error())
		} else {
			state.Status = "completed"
			state.Result = summary
		}
	}()

	return tools.Result{
		Output: fmt.Sprintf("✅ Sub-agent '%s' spawned with ID: %s\nTask: %s\nTarget: %s\n\nUse check_agent(agent_id=%s) to poll for results, or wait_agent(agent_id=%s) to block until done.",
			name, agentID, truncTask(task, 200), target, agentID, agentID),
		Metadata: map[string]any{
			"agent_id":   agentID,
			"agent_name": name,
			"spawned":    true,
		},
	}, nil
}

// checkAgent returns status and partial results of a spawned sub-agent.
func checkAgent(args map[string]string) (tools.Result, error) {
	agentID := args["agent_id"]
	if agentID == "" {
		return tools.Result{}, fmt.Errorf("agent_id is required")
	}

	agentsMu.Lock()
	state, exists := agents[agentID]
	agentsMu.Unlock()

	if !exists {
		// List available agents
		return tools.Result{
			Output: fmt.Sprintf("❌ Agent '%s' not found.\n\nAvailable agents:\n%s", agentID, listAllAgents()),
		}, nil
	}

	var b strings.Builder
	elapsed := time.Since(state.StartedAt).Round(time.Second)

	switch state.Status {
	case "running":
		b.WriteString(fmt.Sprintf("🔄 Agent '%s' (%s) — RUNNING for %s\n", state.Name, state.ID, elapsed))
		b.WriteString(fmt.Sprintf("Task: %s\n", truncTask(state.Task, 150)))

		// Show partial results if available
		state.partialMu.Lock()
		if len(state.partialResults) > 0 {
			b.WriteString("\n--- Partial Results ---\n")
			// Show last 5 partial results
			start := 0
			if len(state.partialResults) > 5 {
				start = len(state.partialResults) - 5
			}
			for _, pr := range state.partialResults[start:] {
				b.WriteString(pr + "\n")
			}
		} else {
			b.WriteString("\n(No partial results yet — agent is still working)\n")
		}
		state.partialMu.Unlock()

	case "completed":
		completedElapsed := state.CompletedAt.Sub(state.StartedAt).Round(time.Second)
		b.WriteString(fmt.Sprintf("✅ Agent '%s' (%s) — COMPLETED in %s\n", state.Name, state.ID, completedElapsed))
		b.WriteString("\n--- Results ---\n")
		result := state.Result
		if len(result) > 5000 {
			result = result[:5000] + "\n... [truncated]"
		}
		b.WriteString(result)

	case "failed":
		b.WriteString(fmt.Sprintf("❌ Agent '%s' (%s) — FAILED after %s\n", state.Name, state.ID, elapsed))
		b.WriteString(fmt.Sprintf("Error: %s\n", state.Error))
		if state.Result != "" {
			b.WriteString("\n--- Partial Results ---\n")
			b.WriteString(state.Result)
		}
	}

	return tools.Result{
		Output: b.String(),
		Metadata: map[string]any{
			"agent_id": agentID,
			"status":   state.Status,
			"elapsed":  elapsed.Seconds(),
		},
	}, nil
}

// waitAgent blocks until a sub-agent completes.
func waitAgent(args map[string]string) (tools.Result, error) {
	agentID := args["agent_id"]
	if agentID == "" {
		return tools.Result{}, fmt.Errorf("agent_id is required")
	}

	timeout := 600 // 10 minutes default
	if t := args["timeout"]; t != "" {
		fmt.Sscanf(t, "%d", &timeout)
	}

	agentsMu.Lock()
	state, exists := agents[agentID]
	agentsMu.Unlock()

	if !exists {
		return tools.Result{
			Output: fmt.Sprintf("❌ Agent '%s' not found.\n\nAvailable agents:\n%s", agentID, listAllAgents()),
		}, nil
	}

	// If already done, return immediately
	if state.Status != "running" {
		return checkAgent(args)
	}

	// Poll until done or timeout
	deadline := time.Now().Add(time.Duration(timeout) * time.Second)
	if timeout == 0 {
		deadline = time.Now().Add(24 * time.Hour) // "forever"
	}

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if state.Status != "running" {
				return checkAgent(args)
			}
			if time.Now().After(deadline) {
				elapsed := time.Since(state.StartedAt).Round(time.Second)
				return tools.Result{
					Output: fmt.Sprintf("⏰ Timeout waiting for agent '%s' (%s) after %s. Agent is still running.\nUse check_agent to poll later, or wait_agent with a longer timeout.",
						state.Name, state.ID, elapsed),
					Metadata: map[string]any{
						"agent_id": agentID,
						"status":   "timeout",
					},
				}, nil
			}
		}
	}
}

// AddPartialResult adds a partial result to a running sub-agent (called from agent event handler).
func AddPartialResult(agentID string, result string) {
	agentsMu.Lock()
	state, exists := agents[agentID]
	agentsMu.Unlock()

	if !exists || state.Status != "running" {
		return
	}

	state.partialMu.Lock()
	defer state.partialMu.Unlock()

	// Keep last 50 partial results
	state.partialResults = append(state.partialResults, result)
	if len(state.partialResults) > 50 {
		state.partialResults = state.partialResults[len(state.partialResults)-50:]
	}
}

// GetRunningCount returns the number of running sub-agents.
func GetRunningCount() int {
	agentsMu.Lock()
	defer agentsMu.Unlock()
	count := 0
	for _, a := range agents {
		if a.Status == "running" {
			count++
		}
	}
	return count
}

// helpers

func listRunningAgents() string {
	agentsMu.Lock()
	defer agentsMu.Unlock()
	var b strings.Builder
	for _, a := range agents {
		if a.Status == "running" {
			elapsed := time.Since(a.StartedAt).Round(time.Second)
			b.WriteString(fmt.Sprintf("  - %s (%s): %s — running for %s\n", a.Name, a.ID, truncTask(a.Task, 80), elapsed))
		}
	}
	if b.Len() == 0 {
		return "  (none)"
	}
	return b.String()
}

func listAllAgents() string {
	agentsMu.Lock()
	defer agentsMu.Unlock()
	var b strings.Builder
	for _, a := range agents {
		elapsed := time.Since(a.StartedAt).Round(time.Second)
		b.WriteString(fmt.Sprintf("  - %s (%s): %s [%s] — %s\n", a.Name, a.ID, truncTask(a.Task, 80), a.Status, elapsed))
	}
	if b.Len() == 0 {
		return "  (none)"
	}
	return b.String()
}

func truncTask(s string, max int) string {
	if len(s) > max {
		return s[:max] + "..."
	}
	return s
}
