package tools

import (
	"bytes"
	"os/exec"
)

// RunCommand executes an external command and returns its output.
func RunCommand(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		if stderr.Len() > 0 {
			return "", &CommandError{Err: err, Stderr: stderr.String()}
		}
		return "", err
	}

	return stdout.String(), nil
}

// CommandError wraps an exec error with stderr.
type CommandError struct {
	Err    error
	Stderr string
}

func (e *CommandError) Error() string {
	return e.Err.Error() + ": " + e.Stderr
}
