// Package browser provides browser automation tools via go-rod/rod.
package browser

import (
	"encoding/base64"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/launcher"
	"github.com/go-rod/rod/lib/proto"

	"github.com/xalgord/xalgorix/internal/config"
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
		Description: "Control a headless Chromium browser. Actions: launch, goto, snapshot, click, type, scroll, screenshot, get_html, execute_js, close, new_tab, switch_tab.",
		Parameters: []tools.Parameter{
			{Name: "command", Description: "Browser action: launch, goto, snapshot, click, type, scroll, screenshot, get_html, execute_js, close, new_tab, switch_tab", Required: true},
			{Name: "url", Description: "URL to navigate to (for launch/goto)", Required: false},
			{Name: "selector", Description: "CSS selector or semantic @eX ID from snapshot (for click/type)", Required: false},
			{Name: "text", Description: "Text to type (for type)", Required: false},
			{Name: "code", Description: "JavaScript code to execute (for execute_js)", Required: false},
			{Name: "direction", Description: "Scroll direction: up or down (for scroll)", Required: false},
			{Name: "tab_id", Description: "Tab ID (for switch_tab)", Required: false},
			{Name: "proxy", Description: "Proxy: 'caido', 'none', or proxy URL", Required: false},
		},
		Execute: browserAction,
	})
}

// detectCaidoPort detects the Caido proxy port.
func detectCaidoPort() int {
	cfg := config.Get()
	if cfg.CaidoPort > 0 {
		return cfg.CaidoPort
	}
	return 8080
}

func ensureBrowser(proxy string) error {
	mu.Lock()
	defer mu.Unlock()

	if browser != nil {
		return nil
	}

	path, exists := launcher.LookPath()
	if !exists {
		// Manual fallback check for common Linux paths
		fallbacks := []string{
			"/usr/bin/chromium",
			"/usr/bin/google-chrome",
			"/usr/bin/chromium-browser",
			"/usr/bin/google-chrome-stable",
			"/snap/bin/chromium",
		}
		for _, p := range fallbacks {
			if _, err := os.Stat(p); err == nil {
				path = p
				exists = true
				break
			}
		}
	}

	if !exists {
		return fmt.Errorf("Chromium/Chrome not found. Install with: sudo apt install chromium")
	}

	ln := launcher.New().
		Bin(path).
		Headless(true).
		Set("no-sandbox").
		Set("disable-dev-shm-usage").
		Set("disable-gpu")

	if proxy == "caido" {
		caidoPort := detectCaidoPort()
		ln = ln.Set("proxy-server", fmt.Sprintf("http://127.0.0.1:%d", caidoPort)).
			Set("ignore-certificate-errors", "true")
	} else if proxy != "" && proxy != "none" {
		ln = ln.Set("proxy-server", proxy).
			Set("ignore-certificate-errors", "true")
	}

	u := ln.MustLaunch()

	browser = rod.New().ControlURL(u).MustConnect()
	return nil
}

func browserAction(args map[string]string) (tools.Result, error) {
	command := args["command"]

	switch command {
	case "launch":
		return launchBrowser(args["url"], args["proxy"])
	case "goto":
		return navigateTo(args["url"])
	case "snapshot":
		return takeSnapshot()
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

func launchBrowser(url, proxy string) (tools.Result, error) {
	if err := ensureBrowser(proxy); err != nil {
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

func parseSelector(selector string) string {
	if strings.HasPrefix(selector, "@e") {
		return fmt.Sprintf(`[data-xalgo-id="%s"]`, strings.TrimPrefix(selector, "@"))
	}
	return selector
}

func clickElement(selector string) (tools.Result, error) {
	if page == nil {
		return tools.Result{}, fmt.Errorf("browser not launched")
	}

	selector = parseSelector(selector)
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

	selector = parseSelector(selector)
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

func takeSnapshot() (tools.Result, error) {
	if page == nil {
		return tools.Result{}, fmt.Errorf("browser not launched")
	}

	script := `() => {
		let output = [];
		let counter = 1;
		const elements = document.querySelectorAll('a, button, input, select, textarea, [role="button"], [role="link"], [tabindex]:not([tabindex="-1"])');
		
		elements.forEach(el => {
			const rect = el.getBoundingClientRect();
			if (rect.width === 0 || rect.height === 0) return;
			const style = window.getComputedStyle(el);
			if (style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0') return;
			
			let id = 'e' + counter++;
			el.setAttribute('data-xalgo-id', id);
			
			let tag = el.tagName.toLowerCase();
			let type = el.type ? '(' + el.type + ')' : '';
			let text = (el.innerText || el.value || el.placeholder || el.getAttribute('aria-label') || el.alt || '').trim().replace(/\n/g, ' ').substring(0, 50);
			if (!text && tag !== 'input' && tag !== 'select') return;
			
			output.push('[@' + id + '] ' + tag + type + ' "' + text + '"');
		});
		
		return output.join('\n');
	}`

	result, err := page.Eval(script)
	if err != nil {
		return tools.Result{}, fmt.Errorf("snapshot failed: %w", err)
	}

	return tools.Result{
		Output: "Interactive Elements Tree:\n\n" + result.Value.String(),
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

	cleanupBrowserLocked()

	return tools.Result{Output: "Browser closed"}, nil
}

// cleanupBrowserLocked closes browser resources (must hold mu).
func cleanupBrowserLocked() {
	if browser != nil {
		browser.MustClose()
		browser = nil
		page = nil
		pages = make(map[string]*rod.Page)
	}
}

// CleanupBrowser safely closes any open browser and resets state.
// Called between scan phases and on agent stop to prevent stale connection usage.
func CleanupBrowser() {
	mu.Lock()
	defer mu.Unlock()
	if browser != nil {
		// Use recover to handle panics from already-dead browser processes
		func() {
			defer func() { recover() }()
			browser.MustClose()
		}()
		browser = nil
		page = nil
		pages = make(map[string]*rod.Page)
	}
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
