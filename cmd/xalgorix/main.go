// Xalgorix — Autonomous AI Pentesting Engine
package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/xalgord/xalgorix/internal/config"
	"github.com/xalgord/xalgorix/internal/tui"
	"github.com/xalgord/xalgorix/internal/web"
)

const version = "0.1.0"

func main() {
	args := parseArgs()

	if args.version {
		fmt.Printf("xalgorix v%s\n", version)
		os.Exit(0)
	}

	if args.update {
		fmt.Println("Updating xalgorix to latest version...")
		cmd := exec.Command("go", "install", "github.com/xalgord/xalgorix/cmd/xalgorix@latest")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			fmt.Fprintf(os.Stderr, "Update failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("✅ Updated successfully!")
		os.Exit(0)
	}

	cfg := config.Get()

	if args.model != "" {
		cfg.LLM = args.model
	}

	// Web UI mode — no target required at launch
	if args.webUI {
		if err := cfg.Validate(); err != nil {
			fmt.Fprintf(os.Stderr, "Configuration error: %s\n\n", err)
			fmt.Fprintf(os.Stderr, "Set your model:     export XALGORIX_LLM='openai/gpt-5.4'\n")
			fmt.Fprintf(os.Stderr, "Set your API key:    export XALGORIX_API_KEY='sk-...'\n")
			os.Exit(1)
		}

		port := args.port
		if port == 0 {
			port = 1337
		}

		fmt.Print(tui.Banner)
		fmt.Println()
		fmt.Printf("\n  Xalgorix Web UI starting on port %d...\n", port)
		fmt.Printf("  Open http://localhost:%d in your browser\n\n", port)

		srv := web.NewServer(cfg, port)
		if err := srv.Start(); err != nil {
			fmt.Fprintf(os.Stderr, "Server error: %v\n", err)
			os.Exit(1)
		}
		return
	}

	// CLI/TUI mode — target required
	if len(args.targets) == 0 {
		fmt.Fprintf(os.Stderr, "Error: at least one --target is required (or use --web for Web UI)\n\n")
		printUsage()
		os.Exit(1)
	}

	if err := cfg.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "Configuration error: %s\n\n", err)
		fmt.Fprintf(os.Stderr, "Set your model:     export XALGORIX_LLM='openai/gpt-5.4'\n")
		fmt.Fprintf(os.Stderr, "Set your API key:    export XALGORIX_API_KEY='sk-...'\n")
		os.Exit(1)
	}

	// Default to CLI mode (no TUI)
	tui.RunCLI(cfg, args.targets, args.instruction)
}

type cliArgs struct {
	targets     []string
	instruction string
	model       string
	version     bool
	update      bool
	webUI       bool
	port        int
}

func parseArgs() cliArgs {
	var args cliArgs

	osArgs := os.Args[1:]
	for i := 0; i < len(osArgs); i++ {
		switch osArgs[i] {
		case "--target", "-t":
			if i+1 < len(osArgs) {
				i++
				args.targets = append(args.targets, osArgs[i])
			}
		case "--instruction", "-i":
			if i+1 < len(osArgs) {
				i++
				args.instruction = osArgs[i]
			}
		case "--model", "-m":
			if i+1 < len(osArgs) {
				i++
				args.model = osArgs[i]
			}
		case "--port", "-p":
			if i+1 < len(osArgs) {
				i++
				fmt.Sscanf(osArgs[i], "%d", &args.port)
			}
		case "--web", "-w":
			args.webUI = true
		case "--update", "-up":
			args.update = true
		case "--version", "-v":
			args.version = true
		case "--help", "-h":
			printUsage()
			os.Exit(0)
		default:
			if strings.HasPrefix(osArgs[i], "--target=") {
				args.targets = append(args.targets, strings.TrimPrefix(osArgs[i], "--target="))
			} else if strings.HasPrefix(osArgs[i], "--instruction=") {
				args.instruction = strings.TrimPrefix(osArgs[i], "--instruction=")
			} else if strings.HasPrefix(osArgs[i], "--model=") {
				args.model = strings.TrimPrefix(osArgs[i], "--model=")
			} else if strings.HasPrefix(osArgs[i], "--port=") {
				fmt.Sscanf(strings.TrimPrefix(osArgs[i], "--port="), "%d", &args.port)
			}
		}
	}

	return args
}

func printUsage() {
	fmt.Print(tui.Banner)
	fmt.Println()
	fmt.Println()
	fmt.Println("  Autonomous AI Pentesting Engine")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  xalgorix --web                  Start the Web UI (default port 1337)")
	fmt.Println("  xalgorix --target <url> [flags]  Run a scan in CLI mode")
	fmt.Println()
	fmt.Println("Modes:")
	fmt.Println("  -w, --web                 Launch the Web UI dashboard")
	fmt.Println("  -p, --port <port>         Web UI port (default: 1337)")
	fmt.Println()
	fmt.Println("CLI Flags:")
	fmt.Println("  -t, --target <url>        Target URL, IP, or local path (repeatable)")
	fmt.Println("  -i, --instruction <text>  Custom instructions for the agent")
	fmt.Println("  -m, --model <name>        LLM model (overrides XALGORIX_LLM)")
	fmt.Println("  -v, --version             Show version")
	fmt.Println("  -up, --update             Update to latest version")
	fmt.Println("  -h, --help                Show help")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  xalgorix --web")
	fmt.Println("  xalgorix --web --port 8080")
	fmt.Println("  xalgorix --target https://example.com")
	fmt.Println("  xalgorix --target https://example.com --instruction \"Focus on auth\"")
	fmt.Println()
	fmt.Println("Environment:")
	fmt.Println("  XALGORIX_LLM              Model name (e.g. minimax/MiniMax-M2.5)")
	fmt.Println("  XALGORIX_API_KEY           API key")
	fmt.Println("  XALGORIX_API_BASE          API base URL")
	fmt.Println("  XALGORIX_MAX_ITERATIONS    Max iterations (0 = unlimited)")
	fmt.Println()
}
