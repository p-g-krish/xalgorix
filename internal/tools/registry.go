// Package tools provides the tool registry and execution framework.
package tools

import (
	"fmt"
	"strings"
	"sync"
)

// Tool represents a registered tool that the agent can call.
type Tool struct {
	Name        string
	Description string
	Parameters  []Parameter
	Execute     func(args map[string]string) (Result, error)
}

// Parameter describes a tool parameter.
type Parameter struct {
	Name        string
	Description string
	Required    bool
}

// Result is the output of a tool execution.
type Result struct {
	Output   string         `json:"output"`
	Error    string         `json:"error,omitempty"`
	Success  bool           `json:"success"`
	Metadata map[string]any `json:"metadata,omitempty"`
}

// Registry holds all registered tools.
type Registry struct {
	mu    sync.RWMutex
	tools map[string]*Tool
}

// NewRegistry creates a new tool registry.
func NewRegistry() *Registry {
	return &Registry{
		tools: make(map[string]*Tool),
	}
}

// Register adds a tool to the registry.
func (r *Registry) Register(t *Tool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.tools[t.Name] = t
}

// Get returns a tool by name.
func (r *Registry) Get(name string) (*Tool, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	t, ok := r.tools[name]
	return t, ok
}

// List returns all registered tool names.
func (r *Registry) List() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	names := make([]string, 0, len(r.tools))
	for name := range r.tools {
		names = append(names, name)
	}
	return names
}

// Execute runs a tool by name with the given arguments.
func (r *Registry) Execute(name string, args map[string]string) (Result, error) {
	tool, ok := r.Get(name)
	if !ok {
		return Result{}, fmt.Errorf("unknown tool: %s", name)
	}

	// Map _raw fallback to first required parameter if needed
	if raw, hasRaw := args["_raw"]; hasRaw {
		for _, p := range tool.Parameters {
			if p.Required {
				if _, exists := args[p.Name]; !exists {
					args[p.Name] = raw
				}
			}
		}
		delete(args, "_raw")
	}

	// Validate required parameters
	for _, p := range tool.Parameters {
		if p.Required {
			if v, exists := args[p.Name]; !exists || strings.TrimSpace(v) == "" {
				return Result{}, fmt.Errorf("missing required parameter '%s' for tool '%s'", p.Name, name)
			}
		}
	}

	result, err := tool.Execute(args)
	if err != nil {
		return Result{
			Output:  "",
			Error:   err.Error(),
			Success: false,
		}, nil
	}

	result.Success = true
	return result, nil
}

// SchemaXML generates XML schema for all tools (for the system prompt).
func (r *Registry) SchemaXML() string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	xml := "<tools>\n"
	for _, t := range r.tools {
		xml += fmt.Sprintf("  <tool name=\"%s\">\n", t.Name)
		xml += fmt.Sprintf("    <description>%s</description>\n", t.Description)
		if len(t.Parameters) > 0 {
			xml += "    <parameters>\n"
			for _, p := range t.Parameters {
				req := ""
				if p.Required {
					req = " required=\"true\""
				}
				xml += fmt.Sprintf("      <parameter name=\"%s\"%s>%s</parameter>\n",
					p.Name, req, p.Description)
			}
			xml += "    </parameters>\n"
		}
		xml += "  </tool>\n"
	}
	xml += "</tools>\n"
	return xml
}
