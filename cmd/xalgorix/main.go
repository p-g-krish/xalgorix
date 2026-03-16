// Xalgorix — Autonomous AI Pentesting Engine
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/xalgord/xalgorix/internal/config"
	"github.com/xalgord/xalgorix/internal/tui"
	"github.com/xalgord/xalgorix/internal/web"
)

const version = "0.10.8"

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

	// Handle restart command
	if args.restart {
		handleRestart()
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
		
		// Get the latest release version from GitHub
		resp, err := http.Get("https://api.github.com/repos/xalgord/xalgorix/releases/latest")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to check for updates: %v\n", err)
			os.Exit(1)
		}
		defer resp.Body.Close()
		
		var release struct {
			TagName string `json:"tag_name"`
			Assets  []struct {
				Name string `json:"name"`
				URL  string `json:"browser_download_url"`
			} `json:"assets"`
		}
		
		if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to parse release info: %v\n", err)
			os.Exit(1)
		}
		
		// Find the linux amd64 binary
		var downloadURL string
		for _, asset := range release.Assets {
			if strings.Contains(asset.Name, "linux") && strings.Contains(asset.Name, "amd64") {
				downloadURL = asset.URL
				break
			}
		}
		
		if downloadURL == "" {
			fmt.Fprintln(os.Stderr, "No suitable binary found for this platform")
			os.Exit(1)
		}
		
		// Download the binary
		fmt.Printf("Downloading %s...\n", release.TagName)
		
		req, _ := http.NewRequest("GET", downloadURL, nil)
		req.Header.Set("Accept", "application/octet-stream")
		client := &http.Client{}
		resp, err = client.Do(req)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Download failed: %v\n", err)
			os.Exit(1)
		}
		defer resp.Body.Close()
		
		// Write to temp file
		tmpFile, err := os.CreateTemp("", "xalgorix-*")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to create temp file: %v\n", err)
			os.Exit(1)
		}
		defer os.Remove(tmpFile.Name())
		
		_, err = io.Copy(tmpFile, resp.Body)
		tmpFile.Close()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to save download: %v\n", err)
			os.Exit(1)
		}
		
		// Make executable 
		os.Chmod(tmpFile.Name(), 0755)
		
		// Determine install path - use GOPATH if available
		goPath := os.Getenv("GOPATH")
		if goPath == "" {
			goPath = filepath.Join(os.Getenv("HOME"), "go")
		}
		installPath := filepath.Join(goPath, "bin", "xalgorix")
		
		// Create bin directory if needed
		os.MkdirAll(filepath.Join(goPath, "bin"), 0755)
		
		// First try to remove existing binary (might fail if running)
		os.Remove(installPath + ".new")
		
		// Copy to .new extension first
		cmd := exec.Command("cp", tmpFile.Name(), installPath+".new")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			// Try with sudo
			cmd = exec.Command("sudo", "cp", tmpFile.Name(), installPath+".new")
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			if err := cmd.Run(); err != nil {
				fmt.Fprintf(os.Stderr, "Failed to install binary: %v\n", err)
				os.Exit(1)
			}
		}
		
		// Rename to actual path (atomic on same filesystem)
		os.Rename(installPath+".new", installPath)
		
		fmt.Println("✅ Updated successfully!")
		
		// Show the new version
		verCmd := exec.Command(installPath, "--version")
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
		// Check if .xalgorix.env exists and is valid
		if err := config.CheckEnvFile(); err != nil {
			fmt.Fprintf(os.Stderr, "\n❌ %s\n\n", err)
			os.Exit(1)
		}

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
	start       bool
	stop        bool
	restart     bool
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
		case "--version", "-v":
			args.version = true
		case "--start":
			args.start = true
		case "--stop":
			args.stop = true
		case "--restart":
			args.restart = true
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
	fmt.Println()
	fmt.Println("Service Commands:")
	fmt.Println("  --start                   Install and start as systemd service")
	fmt.Println("  --stop                    Stop the service")
	fmt.Println("  --restart                 Restart the service")
	fmt.Println("  --uninstall               Remove from system")
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

// handleStart installs and starts xalgorix as a systemd service
func handleStart() {
	// Determine install path
	goPath := os.Getenv("GOPATH")
	if goPath == "" {
		goPath = filepath.Join(os.Getenv("HOME"), "go")
	}
	installPath := filepath.Join(goPath, "bin", "xalgorix")
	
	// Check if binary exists
	if _, err := os.Stat(installPath); os.IsNotExist(err) {
		fmt.Printf("❌ Xalgorix not found at %s\n", installPath)
		fmt.Println("   Install with: xalgorix --update")
		os.Exit(1)
	}

	// Kill any existing xalgorix processes first
	exec.Command("pkill", "-f", "xalgorix.*--web").Run()
	time.Sleep(1 * time.Second)
	
	// Also kill anything using port 1337
	exec.Command("fuser", "-k", "1337/tcp").Run()
	time.Sleep(1 * time.Second)

	// Create systemd service file
	serviceContent := fmt.Sprintf(`[Unit]
Description=Xalgorix - Autonomous AI Pentesting Engine
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/root
Environment="PATH=$HOME/go/bin:/home/vulture/go/bin:$HOME/.local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
Environment="GOPATH=/root/.go"
Environment="GOPATH=/root/go"
EnvironmentFile=%s/.xalgorix.env
ExecStart=%s --web
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
`, os.Getenv("HOME"), installPath)
	// Try to write service file (requires sudo)
	servicePath := "/etc/systemd/system/xalgorix.service"
	err := os.WriteFile(servicePath, []byte(serviceContent), 0644)
	
	if err != nil {
		// Try with sudo
		cmd := exec.Command("sudo", "tee", servicePath)
		cmd.Stdin = strings.NewReader(serviceContent)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			fmt.Fprintf(os.Stderr, "❌ Failed to create service file (need sudo): %v\n", err)
			fmt.Println("   Trying to start in background mode...")
			startBackground()
			return
		}
	}

	// Reload systemd and enable service
	var cmd *exec.Cmd
	cmd = exec.Command("systemctl", "daemon-reload")
	cmd.Run()

	cmd = exec.Command("systemctl", "enable", "xalgorix")
	if err := cmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "⚠️  Failed to enable service: %v\n", err)
	}

	// Start the service
	cmd = exec.Command("systemctl", "start", "xalgorix")
	if err := cmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "❌ Failed to start xalgorix service: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("✅ Xalgorix installed and started as systemd service!")
	fmt.Println("   Web UI: http://localhost:1337")
	fmt.Println("   Logs:   journalctl -u xalgorix -f")
	fmt.Println("   Status: systemctl status xalgorix")
}

func startBackground() {
	logFile, err := os.OpenFile("/tmp/xalgorix.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ Failed to open log file: %v\n", err)
		os.Exit(1)
	}

	// Use GOPATH
	goPath := os.Getenv("GOPATH")
	if goPath == "" {
		goPath = filepath.Join(os.Getenv("HOME"), "go")
	}
	installPath := filepath.Join(goPath, "bin", "xalgorix")
	
	// Start via bash to source env file
	startCmd := exec.Command("/bin/bash", "-c", "source /root/.xalgorix.env && "+installPath+" --web")
	startCmd.Stdout = logFile
	startCmd.Stderr = logFile
	startCmd.Env = os.Environ()

	if err := startCmd.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "❌ Failed to start xalgorix: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("✅ Xalgorix started in background!")
	fmt.Println("   Web UI: http://localhost:1337")
	fmt.Println("   Logs:   tail -f /tmp/xalgorix.log")
	fmt.Printf("   PID:    %d\n", startCmd.Process.Pid)
}

// handleStop stops the xalgorix service
func handleStop() {
	// Try to send stop notification to Discord first
	go func() {
		resp, err := http.Get("http://localhost:1337/api/stop-notify")
		if err == nil {
			resp.Body.Close()
		}
	}()
	
	// Small delay to let notification send
	time.Sleep(500 * time.Millisecond)
	
	// Try systemctl first (with sudo)
	cmd := exec.Command("sudo", "systemctl", "stop", "xalgorix")
	err := cmd.Run()
	
	if err != nil {
		// Fallback: pkill
		cmd = exec.Command("pkill", "-f", "xalgorix")
		cmd.Run()
	}
	
	fmt.Println("✅ Xalgorix stopped!")
}

// handleRestart restarts the xalgorix service
func handleRestart() {
	// Try systemctl first (with sudo)
	cmd := exec.Command("sudo", "systemctl", "restart", "xalgorix")
	err := cmd.Run()
	
	if err != nil {
		// Fallback: stop then start
		handleStop()
		startBackground()
		return
	}
	
	fmt.Println("✅ Xalgorix restarted!")
	fmt.Println("   Web UI: http://localhost:1337")
}

// handleUninstall removes xalgorix from the system
func handleUninstall() {
	fmt.Println("🗑️  Uninstalling Xalgorix...")
	
	// Stop the service first
	cmd := exec.Command("pkill", "-f", "xalgorix")
	cmd.Run()
	
	// Determine install path
	goPath := os.Getenv("GOPATH")
	if goPath == "" {
		goPath = filepath.Join(os.Getenv("HOME"), "go")
	}
	installPath := filepath.Join(goPath, "bin", "xalgorix")
	
	// Remove binary
	if _, err := os.Stat(installPath); err == nil {
		rmCmd := exec.Command("rm", installPath)
		rmCmd.Stdout = os.Stdout
		rmCmd.Stderr = os.Stderr
		if err := rmCmd.Run(); err != nil {
			fmt.Fprintf(os.Stderr, "❌ Failed to remove binary: %v\n", err)
		} else {
			fmt.Printf("✅ Removed %s\n", installPath)
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
