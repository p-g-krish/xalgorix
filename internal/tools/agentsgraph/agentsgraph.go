// Package agentsgraph provides multi-agent delegation tools.
package agentsgraph

import (
	"fmt"
	"strings"
	"time"

	"github.com/xalgord/xalgorix/internal/tools"
)

// AgentRunner is a function that runs a sub-agent. This breaks the import cycle
// between agent and agentsgraph. The agent package injects this at registration time.
type AgentRunner func(name string, targets []string, task string) (string, error)

var runner AgentRunner

// Register adds multi-agent tools to the registry.
// The agentRunner function is injected to break the import cycle.
func Register(r *tools.Registry, agentRunner AgentRunner) {
	runner = agentRunner

	r.Register(&tools.Tool{
		Name:        "create_agent",
		Description: "Create and run a sub-agent for a specific task. The sub-agent has all the same tools and can work independently.",
		Parameters: []tools.Parameter{
			{Name: "name", Description: "Name for the sub-agent (e.g. 'SQLi Scanner')", Required: true},
			{Name: "task", Description: "Task description for the sub-agent", Required: true},
			{Name: "target", Description: "Target URL/path for the sub-agent", Required: false},
		},
		Execute: createAgent,
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
