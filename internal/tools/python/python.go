// Package python provides the python_action tool via subprocess.
package python

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/xalgord/xalgorix/internal/config"
	"github.com/xalgord/xalgorix/internal/tools"
)

// Register adds the python_action tool to the registry.
func Register(r *tools.Registry) {
	r.Register(&tools.Tool{
		Name:        "python_action",
		Description: "Execute Python code in a subprocess. Python 3 must be installed.",
		Parameters: []tools.Parameter{
			{Name: "code", Description: "Python code to execute", Required: true},
			{Name: "timeout", Description: "Timeout in seconds (default: 60)", Required: false},
		},
		Execute: executePython,
	})
}

func executePython(args map[string]string) (tools.Result, error) {
	code := args["code"]
	if code == "" {
		return tools.Result{}, fmt.Errorf("code is required")
	}

	timeoutSec := 60
	if t := args["timeout"]; t != "" {
		fmt.Sscanf(t, "%d", &timeoutSec)
	}

	// Find python3
	pythonBin := "python3"
	if _, err := exec.LookPath(pythonBin); err != nil {
		pythonBin = "python"
		if _, err := exec.LookPath(pythonBin); err != nil {
			return tools.Result{}, fmt.Errorf("Python not found. Install python3")
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutSec)*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, pythonBin, "-c", code)
	cmd.Dir = config.Get().Workspace
	cmd.Env = append(os.Environ(), "PYTHONDONTWRITEBYTECODE=1")

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()

	var b strings.Builder
	if stdout.Len() > 0 {
		out := stdout.String()
		if len(out) > 15000 {
			out = out[:15000] + "\n... [OUTPUT TRUNCATED]"
		}
		b.WriteString(out)
	}

	if stderr.Len() > 0 {
		if b.Len() > 0 {
			b.WriteString("\n")
		}
		b.WriteString("STDERR:\n")
		errOut := stderr.String()
		if len(errOut) > 5000 {
			errOut = errOut[:5000] + "\n... [TRUNCATED]"
		}
		b.WriteString(errOut)
	}

	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			b.WriteString(fmt.Sprintf("\n[TIMEOUT: exceeded %ds]", timeoutSec))
		} else if exitErr, ok := err.(*exec.ExitError); ok {
			b.WriteString(fmt.Sprintf("\n[exit code: %d]", exitErr.ExitCode()))
		}
	}

	if b.Len() == 0 {
		b.WriteString("(no output)")
	}

	return tools.Result{Output: b.String()}, nil
}
