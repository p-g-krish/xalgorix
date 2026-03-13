// Package websearch provides web search tools.
package websearch

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/xalgord/xalgorix/internal/tools"
)

// Register adds web search tools to the registry.
func Register(r *tools.Registry) {
	r.Register(&tools.Tool{
		Name:        "web_search",
		Description: "Search the web for information. Uses DuckDuckGo.",
		Parameters: []tools.Parameter{
			{Name: "query", Description: "Search query", Required: true},
			{Name: "max_results", Description: "Maximum results (default: 5)", Required: false},
		},
		Execute: webSearch,
	})
}

func webSearch(args map[string]string) (tools.Result, error) {
	query := args["query"]
	if query == "" {
		return tools.Result{}, fmt.Errorf("query is required")
	}

	maxResults := 5
	if m := args["max_results"]; m != "" {
		fmt.Sscanf(m, "%d", &maxResults)
	}

	// Use DuckDuckGo instant answer API
	ddgURL := fmt.Sprintf("https://api.duckduckgo.com/?q=%s&format=json&no_html=1", url.QueryEscape(query))

	resp, err := http.Get(ddgURL)
	if err != nil {
		return tools.Result{}, fmt.Errorf("search failed: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	var result struct {
		Abstract       string `json:"Abstract"`
		AbstractSource string `json:"AbstractSource"`
		AbstractURL    string `json:"AbstractURL"`
		RelatedTopics  []struct {
			Text     string `json:"Text"`
			FirstURL string `json:"FirstURL"`
		} `json:"RelatedTopics"`
	}

	if err := json.Unmarshal(body, &result); err != nil {
		return tools.Result{Output: fmt.Sprintf("Search for '%s' returned raw data:\n%s", query, truncateStr(string(body), 2000))}, nil
	}

	var b strings.Builder
	b.WriteString(fmt.Sprintf("Search results for: %s\n\n", query))

	if result.Abstract != "" {
		b.WriteString(fmt.Sprintf("📋 %s\n", result.Abstract))
		if result.AbstractURL != "" {
			b.WriteString(fmt.Sprintf("   Source: %s (%s)\n\n", result.AbstractSource, result.AbstractURL))
		}
	}

	count := 0
	for _, topic := range result.RelatedTopics {
		if count >= maxResults {
			break
		}
		if topic.Text != "" {
			count++
			b.WriteString(fmt.Sprintf("%d. %s\n", count, topic.Text))
			if topic.FirstURL != "" {
				b.WriteString(fmt.Sprintf("   %s\n", topic.FirstURL))
			}
			b.WriteString("\n")
		}
	}

	if b.Len() < 50 {
		b.WriteString("No significant results found. Try rephrasing the query.\n")
	}

	return tools.Result{Output: b.String()}, nil
}

func truncateStr(s string, max int) string {
	if len(s) > max {
		return s[:max] + "..."
	}
	return s
}
