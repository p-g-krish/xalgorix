// Package browser provides browser automation tools via go-rod/rod.
package browser

import (
	"encoding/base64"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/launcher"
	"github.com/go-rod/rod/lib/proto"

	"github.com/xalgord/xalgorix/internal/tools"
)

var (
	mu         sync.Mutex
	browser    *rod.Browser
	page       *rod.Page
	pages      map[string]*rod.Page
	nextTab    int
	currentTab string
)

func init() {
	pages = make(map[string]*rod.Page)
	nextTab = 1
}

// Register adds browser tools to the registry.
func Register(r *tools.Registry) {
	r.Register(&tools.Tool{
		Name:        "browser_action",
		Description: "Control a headless Chromium browser. Actions: launch, goto, click, type, scroll, screenshot, get_html, execute_js, close, new_tab, switch_tab.",
		Parameters: []tools.Parameter{
			{Name: "command", Description: "Browser action: launch, goto, click, type, scroll, screenshot, get_html, execute_js, close, new_tab, switch_tab", Required: true},
			{Name: "url", Description: "URL to navigate to (for launch/goto)", Required: false},
			{Name: "selector", Description: "CSS selector for element (for click/type)", Required: false},
			{Name: "text", Description: "Text to type (for type)", Required: false},
			{Name: "code", Description: "JavaScript code to execute (for execute_js)", Required: false},
			{Name: "direction", Description: "Scroll direction: up or down (for scroll)", Required: false},
			{Name: "tab_id", Description: "Tab ID (for switch_tab)", Required: false},
		},
		Execute: browserAction,
	})
}

func ensureBrowser() error {
	mu.Lock()
	defer mu.Unlock()

	if browser != nil {
		return nil
	}

	path, exists := launcher.LookPath()
	if !exists {
		return fmt.Errorf("Chromium/Chrome not found. Install with: sudo apt install chromium")
	}

	u := launcher.New().
		Bin(path).
		Headless(true).
		Set("no-sandbox").
		Set("disable-dev-shm-usage").
		Set("disable-gpu").
		MustLaunch()

	browser = rod.New().ControlURL(u).MustConnect()
	return nil
}

func browserAction(args map[string]string) (tools.Result, error) {
	command := args["command"]

	switch command {
	case "launch":
		return launchBrowser(args["url"])
	case "goto":
		return navigateTo(args["url"])
	case "click":
		return clickElement(args["selector"])
	case "type":
		return typeText(args["selector"], args["text"])
	case "scroll":
		return scrollPage(args["direction"])
	case "screenshot":
		return takeScreenshot()
	case "get_html":
		return getHTML(args["selector"])
	case "execute_js":
		return executeJS(args["code"])
	case "new_tab":
		return newTab(args["url"])
	case "switch_tab":
		return switchTab(args["tab_id"])
	case "close":
		return closeBrowser()
	default:
		return tools.Result{}, fmt.Errorf("unknown browser action: %s", command)
	}
}

func launchBrowser(url string) (tools.Result, error) {
	if err := ensureBrowser(); err != nil {
		return tools.Result{}, err
	}

	p := browser.MustPage()
	tabID := fmt.Sprintf("tab_%d", nextTab)
	nextTab++
	pages[tabID] = p
	currentTab = tabID
	page = p

	if url != "" {
		p.MustNavigate(url).MustWaitStable()
	}

	return pageState("Browser launched", tabID)
}

func navigateTo(url string) (tools.Result, error) {
	if page == nil {
		return tools.Result{}, fmt.Errorf("browser not launched — use launch first")
	}

	page.MustNavigate(url).MustWaitStable()
	return pageState("Navigated", currentTab)
}

func clickElement(selector string) (tools.Result, error) {
	if page == nil {
		return tools.Result{}, fmt.Errorf("browser not launched")
	}

	el, err := page.Timeout(10 * time.Second).Element(selector)
	if err != nil {
		return tools.Result{}, fmt.Errorf("element not found: %s", selector)
	}

	el.MustClick()
	page.MustWaitStable()
	return pageState(fmt.Sprintf("Clicked: %s", selector), currentTab)
}

func typeText(selector, text string) (tools.Result, error) {
	if page == nil {
		return tools.Result{}, fmt.Errorf("browser not launched")
	}

	el, err := page.Timeout(10 * time.Second).Element(selector)
	if err != nil {
		return tools.Result{}, fmt.Errorf("element not found: %s", selector)
	}

	el.MustSelectAllText().MustInput(text)
	return pageState(fmt.Sprintf("Typed into: %s", selector), currentTab)
}

func scrollPage(direction string) (tools.Result, error) {
	if page == nil {
		return tools.Result{}, fmt.Errorf("browser not launched")
	}

	switch strings.ToLower(direction) {
	case "down":
		page.Mouse.MustScroll(0, 500)
	case "up":
		page.Mouse.MustScroll(0, -500)
	default:
		page.Mouse.MustScroll(0, 500)
	}

	time.Sleep(500 * time.Millisecond)
	return pageState(fmt.Sprintf("Scrolled %s", direction), currentTab)
}

func takeScreenshot() (tools.Result, error) {
	if page == nil {
		return tools.Result{}, fmt.Errorf("browser not launched")
	}

	img, err := page.Screenshot(true, &proto.PageCaptureScreenshot{
		Format:  proto.PageCaptureScreenshotFormatPng,
		Quality: nil,
	})
	if err != nil {
		return tools.Result{}, fmt.Errorf("screenshot failed: %w", err)
	}

	b64 := base64.StdEncoding.EncodeToString(img)

	return tools.Result{
		Output: fmt.Sprintf("Screenshot captured (%d bytes)", len(img)),
		Metadata: map[string]any{
			"screenshot": b64,
			"format":     "png",
			"size_bytes": len(img),
		},
	}, nil
}

func getHTML(selector string) (tools.Result, error) {
	if page == nil {
		return tools.Result{}, fmt.Errorf("browser not launched")
	}

	var html string
	if selector != "" {
		el, err := page.Timeout(10 * time.Second).Element(selector)
		if err != nil {
			return tools.Result{}, fmt.Errorf("element not found: %s", selector)
		}
		html, _ = el.HTML()
	} else {
		html = page.MustHTML()
	}

	if len(html) > 20000 {
		html = html[:20000] + "\n\n... [HTML TRUNCATED]"
	}

	return tools.Result{Output: html}, nil
}

func executeJS(code string) (tools.Result, error) {
	if page == nil {
		return tools.Result{}, fmt.Errorf("browser not launched")
	}
	if code == "" {
		return tools.Result{}, fmt.Errorf("code is required")
	}

	result, err := page.Eval(code)
	if err != nil {
		return tools.Result{}, fmt.Errorf("JS error: %w", err)
	}

	return tools.Result{Output: result.Value.String()}, nil
}

func newTab(url string) (tools.Result, error) {
	if browser == nil {
		return tools.Result{}, fmt.Errorf("browser not launched")
	}

	p := browser.MustPage()
	tabID := fmt.Sprintf("tab_%d", nextTab)
	nextTab++
	pages[tabID] = p
	currentTab = tabID
	page = p

	if url != "" {
		p.MustNavigate(url).MustWaitStable()
	}

	return pageState("New tab opened", tabID)
}

func switchTab(tabID string) (tools.Result, error) {
	p, ok := pages[tabID]
	if !ok {
		return tools.Result{}, fmt.Errorf("tab not found: %s (available: %v)", tabID, tabList())
	}

	page = p
	currentTab = tabID
	return pageState("Switched tab", tabID)
}

func closeBrowser() (tools.Result, error) {
	mu.Lock()
	defer mu.Unlock()

	if browser != nil {
		browser.MustClose()
		browser = nil
		page = nil
		pages = make(map[string]*rod.Page)
	}

	return tools.Result{Output: "Browser closed"}, nil
}

func pageState(action, tabID string) (tools.Result, error) {
	if page == nil {
		return tools.Result{Output: action}, nil
	}

	info, _ := page.Info()
	url := ""
	title := ""
	if info != nil {
		url = info.URL
		title = info.Title
	}

	var b strings.Builder
	b.WriteString(fmt.Sprintf("%s\n", action))
	b.WriteString(fmt.Sprintf("  Tab: %s\n", tabID))
	if url != "" {
		b.WriteString(fmt.Sprintf("  URL: %s\n", url))
	}
	if title != "" {
		b.WriteString(fmt.Sprintf("  Title: %s\n", title))
	}

	// List all tabs
	if len(pages) > 1 {
		b.WriteString("  All tabs: ")
		b.WriteString(strings.Join(tabList(), ", "))
		b.WriteString("\n")
	}

	return tools.Result{
		Output: b.String(),
		Metadata: map[string]any{
			"url":    url,
			"title":  title,
			"tab_id": tabID,
		},
	}, nil
}

func tabList() []string {
	tabs := make([]string, 0, len(pages))
	for id := range pages {
		tabs = append(tabs, id)
	}
	return tabs
}
