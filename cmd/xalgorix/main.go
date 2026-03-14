// Xalgorix — Autonomous AI Pentesting Engine
package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/xalgord/xalgorix/internal/config"
	"github.com/xalgord/xalgorix/internal/tui"
	"github.com/xalgord/xalgorix/internal/web"
)

const version = "0.6.3"

func main() {
	args := parseArgs()

	// Handle start command
	if args.start {
		handleStart()
		os.Exit(0)
	}

	// Handle stop command
	if args.stop {
		handleStop()
		os.Exit(0)
	}

	// Handle uninstall command
	if args.uninstall {
		handleUninstall()
		os.Exit(0)
	}

	if args.version {
		fmt.Printf("xalgorix v%s\n", version)
		os.Exit(0)
	}

	if args.update {
		fmt.Println("Updating xalgorix to latest version...")
		cmd := exec.Command("go", "install", "github.com/xalgord/xalgorix/cmd/xalgorix@latest")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		cmd.Env = append(os.Environ(), "GOPROXY=direct")
		if err := cmd.Run(); err != nil {
			fmt.Fprintf(os.Stderr, "Update failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("✅ Updated successfully!")
		
		// Find the new binary and show its version
		goBin := os.Getenv("GOPATH")
		if goBin == "" {
			goBin = filepath.Join(os.Getenv("HOME"), "go")
		}
		newBin := filepath.Join(goBin, "bin", "xalgorix")
		
		// Show the version from the newly installed binary
		verCmd := exec.Command(newBin, "--version")
		verCmd.Stdout = os.Stdout
		verCmd.Stderr = os.Stderr
		verCmd.Run()
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

		// Daemon mode: re-launch in background
		if args.daemon {
			// Build args without -d/--daemon to avoid infinite loop
			var newArgs []string
			for _, a := range os.Args[1:] {
				if a != "-d" && a != "--daemon" {
					newArgs = append(newArgs, a)
				}
			}
			logFile, err := os.OpenFile("/tmp/xalgorix.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Failed to open log file: %v\n", err)
				os.Exit(1)
			}
			cmd := exec.Command(os.Args[0], newArgs...)
			cmd.Stdout = logFile
			cmd.Stderr = logFile
			cmd.Env = os.Environ()
			if err := cmd.Start(); err != nil {
				fmt.Fprintf(os.Stderr, "Failed to start daemon: %v\n", err)
				os.Exit(1)
			}
			fmt.Printf("Xalgorix running in background (PID: %d)\n", cmd.Process.Pid)
			fmt.Printf("  Web UI: http://localhost:%d\n", port)
			fmt.Printf("  Logs:   /tmp/xalgorix.log\n")
			fmt.Printf("  Stop:   kill %d\n", cmd.Process.Pid)
			os.Exit(0)
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
	daemon      bool
	webUI       bool
	port        int
	start       bool
	stop        bool
	uninstall   bool
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
		case "--daemon", "-d":
			args.daemon = true
		case "--version", "-v":
			args.version = true
		case "--start":
			args.start = true
		case "--stop":
			args.stop = true
		case "--uninstall":
			args.uninstall = true
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
	fmt.Println("  -d, --daemon              Run Web UI in background")
	fmt.Println()
	fmt.Println("CLI Flags:")
	fmt.Println("  -t, --target <url>        Target URL, IP, or local path (repeatable)")
	fmt.Println("  -i, --instruction <text>  Custom instructions for the agent")
	fmt.Println("  -m, --model <name>        LLM model (overrides XALGORIX_LLM)")
	fmt.Println("  -v, --version             Show version")
	fmt.Println("  -up, --update             Update to latest version")
	fmt.Println("  --start                  Start as background service")
	fmt.Println("  --stop                   Stop running service")
	fmt.Println("  --uninstall              Uninstall from system")
	fmt.Println("  -h, --help                Show help")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  xalgorix --web")
	fmt.Println("  xalgorix --web --port 8080")
	fmt.Println("  xalgorix --target https://example.com")
	fmt.Println("  xalgorix --target https://example.com --instruction \"Focus on auth\"")
	fmt.Println()
	fmt.Println("Service Commands:")
	fmt.Println("  xalgorix --start      Start Web UI in background")
	fmt.Println("  xalgorix --stop       Stop running Web UI")
	fmt.Println("  xalgorix --uninstall  Remove xalgorix from system")
	fmt.Println()
	fmt.Println("Environment:")
	fmt.Println("  XALGORIX_LLM              Model name (e.g. minimax/MiniMax-M2.5)")
	fmt.Println("  XALGORIX_API_KEY           API key")
	fmt.Println("  XALGORIX_API_BASE          API base URL")
	fmt.Println("  XALGORIX_MAX_ITERATIONS    Max iterations (0 = unlimited)")
	fmt.Println()
}

// handleStart starts xalgorix as a background service
func handleStart() {
	// Check if already running
	cmd := exec.Command("pgrep", "-f", "xalgorix.*--web")
	output, _ := cmd.Output()
	if len(output) > 0 {
		fmt.Println("⚠️  Xalgorix is already running!")
		fmt.Println("   Use: xalgorix --stop to stop it first")
		os.Exit(1)
	}

	// Check if binary exists
	if _, err := os.Stat("/usr/local/bin/xalgorix"); os.IsNotExist(err) {
		fmt.Println("❌ Xalgorix not found at /usr/local/bin/xalgorix")
		fmt.Println("   Install with: go install or ./build.sh --install")
		os.Exit(1)
	}

	// Load env file
	cfg := config.Get()

	// Validate config
	if err := cfg.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "❌ Configuration error: %s\n", err)
		fmt.Fprintf(os.Stderr, "\nSet your model:\n")
		fmt.Fprintf(os.Stderr, "   nano ~/.xalgorix.env\n")
		fmt.Fprintf(os.Stderr, "   XALGORIX_LLM=minimax/MiniMax-M2.5\n")
		fmt.Fprintf(os.Stderr, "   XALGORIX_API_KEY=your_key_here\n")
		os.Exit(1)
	}

	// Start in background
	logFile, err := os.OpenFile("/tmp/xalgorix.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ Failed to open log file: %v\n", err)
		os.Exit(1)
	}

	startCmd := exec.Command("/usr/local/bin/xalgorix", "--web", "--daemon")
	startCmd.Stdout = logFile
	startCmd.Stderr = logFile

	if err := startCmd.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "❌ Failed to start xalgorix: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("✅ Xalgorix started successfully!")
	fmt.Println("   Web UI: http://localhost:1337")
	fmt.Println("   Logs:   tail -f /tmp/xalgorix.log")
}

// handleStop stops the running xalgorix service
func handleStop() {
	// Find and kill xalgorix processes
	cmd := exec.Command("pkill", "-f", "xalgorix.*--web")
	err := cmd.Run()
	
	if err != nil {
		fmt.Println("⚠️  No running xalgorix process found")
	} else {
		fmt.Println("✅ Xalgorix stopped successfully!")
	}
}

// handleUninstall removes xalgorix from the system
func handleUninstall() {
	fmt.Println("🗑️  Uninstalling Xalgorix...")
	
	// Stop the service first
	cmd := exec.Command("pkill", "-f", "xalgorix")
	cmd.Run()
	
	// Remove binary
	if _, err := os.Stat("/usr/local/bin/xalgorix"); err == nil {
		rmCmd := exec.Command("sudo", "rm", "/usr/local/bin/xalgorix")
		rmCmd.Stdout = os.Stdout
		rmCmd.Stderr = os.Stderr
		if err := rmCmd.Run(); err != nil {
			fmt.Fprintf(os.Stderr, "❌ Failed to remove binary: %v\n", err)
		} else {
			fmt.Println("✅ Removed /usr/local/bin/xalgorix")
		}
	}
	
	// Ask about data removal
	fmt.Println()
	fmt.Println("📁 Data directories (not removed automatically):")
	fmt.Println("   ~/.xalgorix/         - Configuration & skills")
	fmt.Println("   ~/xalgorix-data/    - Scan data & reports")
	fmt.Println()
	fmt.Println("To remove data manually:")
	fmt.Println("   rm -rf ~/.xalgorix ~/xalgorix-data")
	
	fmt.Println()
	fmt.Println("✅ Uninstall complete!")
}
