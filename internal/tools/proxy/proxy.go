// Package proxy provides Caido proxy integration tools.
package proxy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os/exec"
	"strconv"
	"strings"

	"github.com/xalgord/xalgorix/internal/config"
	"github.com/xalgord/xalgorix/internal/tools"
)

// Register adds proxy tools to the registry.
func Register(r *tools.Registry) {
	r.Register(&tools.Tool{
		Name:        "send_request",
		Description: "Send an HTTP request through the Caido proxy.",
		Parameters: []tools.Parameter{
			{Name: "method", Description: "HTTP method (GET, POST, PUT, DELETE, etc.)", Required: true},
			{Name: "url", Description: "Target URL", Required: true},
			{Name: "headers", Description: "Request headers as JSON object", Required: false},
			{Name: "body", Description: "Request body", Required: false},
		},
		Execute: sendRequest,
	})

	r.Register(&tools.Tool{
		Name:        "list_requests",
		Description: "List HTTP requests captured by Caido proxy.",
		Parameters: []tools.Parameter{
			{Name: "count", Description: "Number of requests to list (default: 20)", Required: false},
			{Name: "filter", Description: "Filter by URL substring", Required: false},
		},
		Execute: listRequests,
	})
}

func detectCaidoPort() int {
	cfg := config.Get()
	if cfg.CaidoPort > 0 {
		return cfg.CaidoPort
	}

	// Check if Caido is running
	out, err := exec.Command("ss", "-tlnp").Output()
	if err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			if strings.Contains(line, "caido") || strings.Contains(line, ":8080") || strings.Contains(line, ":8081") {
				parts := strings.Fields(line)
				for _, p := range parts {
					if strings.Contains(p, ":") {
						addr := strings.Split(p, ":")
						if port, err := strconv.Atoi(addr[len(addr)-1]); err == nil && port > 0 {
							return port
						}
					}
				}
			}
		}
	}

	// Try common Caido ports
	for _, port := range []int{8080, 8081, 9090} {
		resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d", port))
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode < 500 {
				return port
			}
		}
	}

	return 8080
}

// ensureCaidoRunning tries to install and start Caido if not available
func ensureCaidoRunning() string {
	// Check if caido command exists
	_, err := exec.LookPath("caido")
	if err == nil {
		// Caido is installed, try to start it
		exec.Command("caido", "&")
		return "Caido found, attempting to start..."
	}

	// Try to install Caido (Linux)
	installMsg := `# To use Caido with Xalgorix:
# 1. Download Caido from https://caido.com
# 2. Install and run it
# 3. Set CAIDO_PORT=8080 in ~/.xalgorix.env`

	// Check for snap
	_, err = exec.LookPath("snap")
	if err == nil {
		installMsg = `# Install Caido via snap:
sudo snap install caido
caido &`
	}

	return installMsg
}

func getCaidoGraphQLURL() string {
	port := detectCaidoPort()
	return fmt.Sprintf("http://127.0.0.1:%d/graphql", port)
}

func sendRequest(args map[string]string) (tools.Result, error) {
	method := strings.ToUpper(args["method"])
	targetURL := args["url"]

	var bodyReader io.Reader
	if body := args["body"]; body != "" {
		bodyReader = strings.NewReader(body)
	}

	req, err := http.NewRequest(method, targetURL, bodyReader)
	if err != nil {
		return tools.Result{}, fmt.Errorf("invalid request: %w", err)
	}

	if headersJSON := args["headers"]; headersJSON != "" {
		var headers map[string]string
		if err := json.Unmarshal([]byte(headersJSON), &headers); err == nil {
			for k, v := range headers {
				req.Header.Set(k, v)
			}
		}
	}

	caidoPort := detectCaidoPort()
	
	// Check if Caido is accessible
	checkResp, checkErr := http.Get(fmt.Sprintf("http://127.0.0.1:%d", caidoPort))
	if checkErr != nil || (checkResp != nil && checkResp.StatusCode >= 500) {
		// Caido not running - provide install instructions
		if checkResp != nil {
			checkResp.Body.Close()
		}
		return tools.Result{Output: ensureCaidoRunning()}, nil
	}
	if checkResp != nil {
		checkResp.Body.Close()
	}
	
	proxyURLStr := fmt.Sprintf("http://127.0.0.1:%d", caidoPort)
	proxyURL, _ := url.Parse(proxyURLStr)

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		// Fall back to direct request
		client = &http.Client{}
		resp, err = client.Do(req)
		if err != nil {
			return tools.Result{}, fmt.Errorf("request failed: %w", err)
		}
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)

	var b strings.Builder
	b.WriteString(fmt.Sprintf("HTTP/%s %s\n", resp.Proto, resp.Status))
	for k, vs := range resp.Header {
		for _, v := range vs {
			b.WriteString(fmt.Sprintf("%s: %s\n", k, v))
		}
	}
	b.WriteString("\n")

	bodyStr := string(respBody)
	if len(bodyStr) > 10000 {
		bodyStr = bodyStr[:10000] + "\n\n... [TRUNCATED]"
	}
	b.WriteString(bodyStr)

	return tools.Result{
		Output: b.String(),
		Metadata: map[string]any{
			"status_code": resp.StatusCode,
			"url":         targetURL,
		},
	}, nil
}

func listRequests(args map[string]string) (tools.Result, error) {
	cfg := config.Get()
	if cfg.CaidoAPIToken == "" {
		return tools.Result{Output: "Caido API token not configured. Set CAIDO_API_TOKEN."}, nil
	}

	count := 20
	if c := args["count"]; c != "" {
		fmt.Sscanf(c, "%d", &count)
	}

	query := `query { requests(first: ` + strconv.Itoa(count) + `) { edges { node { id method url response { statusCode } } } } }`

	gqlReq := map[string]any{"query": query}
	body, _ := json.Marshal(gqlReq)

	gqlURL := getCaidoGraphQLURL()
	req, _ := http.NewRequest(http.MethodPost, gqlURL, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+cfg.CaidoAPIToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return tools.Result{}, fmt.Errorf("failed to query Caido: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	return tools.Result{Output: string(respBody)}, nil
}
