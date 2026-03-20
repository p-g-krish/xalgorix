// Package agentmail provides AgentMail API integration for email operations.
package agentmail

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/xalgord/xalgorix/internal/config"
	"github.com/xalgord/xalgorix/internal/tools"
)

const baseURL = "https://api.agentmail.to/v0"

// AgentMail client
type AgentMail struct {
	apiKey string
	pod    string
	http   *http.Client
}

// Message represents an email message
type Message struct {
	ID        string   `json:"id"`
	Subject   string   `json:"subject"`
	From      string   `json:"from"`
	To        string   `json:"to"`
	Body      string   `json:"body"`
	HTMLBody string   `json:"html_body"`
	Date      string   `json:"date"`
	Attachments []Attachment `json:"attachments"`
}

// Attachment represents an email attachment
type Attachment struct {
	ID       string `json:"id"`
	Filename string `json:"filename"`
	Size     int    `json:"size"`
	ContentType string `json:"content_type"`
}

// Inbox represents an email inbox
type Inbox struct {
	ID        string `json:"id"`
	Email     string `json:"email"`
	Domain    string `json:"domain"`
	CreatedAt string `json:"created_at"`
}

// Thread represents an email thread
type Thread struct {
	ID        string    `json:"id"`
	Subject   string    `json:"subject"`
	From      string    `json:"from"`
	To        string    `json:"to"`
	Messages  []Message `json:"messages"`
	CreatedAt string    `json:"created_at"`
	UpdatedAt string    `json:"updated_at"`
}

// New creates a new AgentMail client
func New() *AgentMail {
	cfg := config.Get()
	return &AgentMail{
		apiKey: cfg.AgentMailAPIKey,
		pod:    cfg.AgentMailPod,
		http:   &http.Client{Timeout: 30 * time.Second},
	}
}

// buildAuth builds the authorization header with pod prefix
func (a *AgentMail) buildAuth() string {
	return fmt.Sprintf("ApiKey %s_%s", a.pod, a.apiKey)
}

// isConfigured checks if AgentMail is properly configured
func (a *AgentMail) isConfigured() bool {
	return a.apiKey != "" && a.pod != ""
}

// ListInboxes lists all inboxes
func (a *AgentMail) ListInboxes() ([]Inbox, error) {
	if !a.isConfigured() {
		return nil, fmt.Errorf("AgentMail not configured: set AGENTMAIL_API_KEY and AGENTMAIL_POD environment variables")
	}

	req, err := http.NewRequest("GET", baseURL+"/inboxes", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", a.buildAuth())
	req.Header.Set("Content-Type", "application/json")

	resp, err := a.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("API error: %s - %s", resp.Status, string(body))
	}

	var result struct {
		Inboxes []Inbox `json:"inboxes"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return result.Inboxes, nil
}

// CreateInbox creates a new inbox
func (a *AgentMail) CreateInbox(name string) (*Inbox, error) {
	if !a.isConfigured() {
		return nil, fmt.Errorf("AgentMail not configured: set AGENTMAIL_API_KEY and AGENTMAIL_POD environment variables")
	}

	body := fmt.Sprintf(`{"name":"%s"}`, name)
	req, err := http.NewRequest("POST", baseURL+"/inboxes", strings.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", a.buildAuth())
	req.Header.Set("Content-Type", "application/json")

	resp, err := a.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 201 {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("API error: %s - %s", resp.Status, string(respBody))
	}

	var inbox Inbox
	if err := json.NewDecoder(resp.Body).Decode(&inbox); err != nil {
		return nil, err
	}

	return &inbox, nil
}

// GetInbox gets an inbox by ID
func (a *AgentMail) GetInbox(inboxID string) (*Inbox, error) {
	if !a.isConfigured() {
		return nil, fmt.Errorf("AgentMail not configured")
	}

	req, err := http.NewRequest("GET", baseURL+"/inboxes/"+inboxID, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", a.buildAuth())

	resp, err := a.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("API error: %s", resp.Status)
	}

	var inbox Inbox
	if err := json.NewDecoder(resp.Body).Decode(&inbox); err != nil {
		return nil, err
	}

	return &inbox, nil
}

// ListMessages lists messages in an inbox
func (a *AgentMail) ListMessages(inboxID string) ([]Message, error) {
	if !a.isConfigured() {
		return nil, fmt.Errorf("AgentMail not configured")
	}

	req, err := http.NewRequest("GET", baseURL+"/inboxes/"+inboxID+"/messages", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", a.buildAuth())

	resp, err := a.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("API error: %s", resp.Status)
	}

	var result struct {
		Messages []Message `json:"messages"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return result.Messages, nil
}

// GetMessage gets a specific message
func (a *AgentMail) GetMessage(inboxID, messageID string) (*Message, error) {
	if !a.isConfigured() {
		return nil, fmt.Errorf("AgentMail not configured")
	}

	req, err := http.NewRequest("GET", baseURL+"/inboxes/"+inboxID+"/messages/"+messageID, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", a.buildAuth())

	resp, err := a.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("API error: %s", resp.Status)
	}

	var msg Message
	if err := json.NewDecoder(resp.Body).Decode(&msg); err != nil {
		return nil, err
	}

	return &msg, nil
}

// WaitForEmail waits for an email with a specific subject or sender
func (a *AgentMail) WaitForEmail(inboxID, subject string, timeout time.Duration) (*Message, error) {
	if !a.isConfigured() {
		return nil, fmt.Errorf("AgentMail not configured")
	}

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	timeoutChan := time.After(timeout)

	for {
		select {
		case <-timeoutChan:
			return nil, fmt.Errorf("timeout waiting for email with subject: %s", subject)
		case <-ticker.C:
			messages, err := a.ListMessages(inboxID)
			if err != nil {
				continue
			}
			for _, msg := range messages {
				if strings.Contains(strings.ToLower(msg.Subject), strings.ToLower(subject)) {
					return &msg, nil
				}
			}
		}
	}
}

// SendEmail sends an email from an inbox
func (a *AgentMail) SendEmail(inboxID, to, subject, body string) error {
	if !a.isConfigured() {
		return fmt.Errorf("AgentMail not configured")
	}

	jsonBody := fmt.Sprintf(`{
		"to":"%s",
		"subject":"%s",
		"body":"%s"
	}`, to, subject, body)

	req, err := http.NewRequest("POST", baseURL+"/inboxes/"+inboxID+"/messages/send", strings.NewReader(jsonBody))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", a.buildAuth())
	req.Header.Set("Content-Type", "application/json")

	resp, err := a.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 201 && resp.StatusCode != 200 {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("API error: %s - %s", resp.Status, string(respBody))
	}

	return nil
}

// Register registers the agentmail tool with the registry
func Register(r *tools.Registry) {
	am := New()

	// Check if configured
	if !am.isConfigured() {
		return // Skip registration if not configured
	}

	r.Register(&tools.Tool{
		Name:        "agentmail",
		Description: "AgentMail email operations - create inboxes, send/receive emails, wait for verification codes. Use this for sign-up verification and email testing.",
		Parameters: []tools.Parameter{
			{Name: "action", Description: "Action: list_inboxes, create_inbox, get_inbox, list_messages, get_message, send_email, wait_for_email", Required: true},
			{Name: "inbox_id", Description: "Inbox ID (for most actions)", Required: false},
			{Name: "name", Description: "Inbox name (for create_inbox)", Required: false},
			{Name: "to", Description: "Recipient email (for send_email)", Required: false},
			{Name: "subject", Description: "Email subject (for send_email, wait_for_email)", Required: false},
			{Name: "body", Description: "Email body (for send_email)", Required: false},
			{Name: "message_id", Description: "Message ID (for get_message)", Required: false},
			{Name: "timeout", Description: "Timeout in seconds for wait_for_email (default: 120)", Required: false},
		},
		Execute: func(args map[string]string) (tools.Result, error) {
			action := args["action"]
			var output string

			switch action {
			case "list_inboxes":
				inboxes, err := am.ListInboxes()
				if err != nil {
					return tools.Result{Output: "Error: " + err.Error()}, nil
				}
				for _, ib := range inboxes {
					output += fmt.Sprintf("Inbox: %s | Email: %s\n", ib.ID, ib.Email)
				}
				if output == "" {
					output = "No inboxes found"
				}

			case "create_inbox":
				name := args["name"]
				inbox, err := am.CreateInbox(name)
				if err != nil {
					return tools.Result{Output: "Error: " + err.Error()}, nil
				}
				output = fmt.Sprintf("Created inbox: %s | Email: %s", inbox.ID, inbox.Email)

			case "get_inbox":
				inboxID := args["inbox_id"]
				inbox, err := am.GetInbox(inboxID)
				if err != nil {
					return tools.Result{Output: "Error: " + err.Error()}, nil
				}
				output = fmt.Sprintf("Inbox: %s\nEmail: %s\nDomain: %s\nCreated: %s", inbox.ID, inbox.Email, inbox.Domain, inbox.CreatedAt)

			case "list_messages":
				inboxID := args["inbox_id"]
				messages, err := am.ListMessages(inboxID)
				if err != nil {
					return tools.Result{Output: "Error: " + err.Error()}, nil
				}
				for _, m := range messages {
					output += fmt.Sprintf("From: %s | Subject: %s | Date: %s\n", m.From, m.Subject, m.Date)
				}
				if output == "" {
					output = "No messages found"
				}

			case "get_message":
				inboxID := args["inbox_id"]
				msgID := args["message_id"]
				msg, err := am.GetMessage(inboxID, msgID)
				if err != nil {
					return tools.Result{Output: "Error: " + err.Error()}, nil
				}
				output = fmt.Sprintf("From: %s\nTo: %s\nSubject: %s\n\n%s", msg.From, msg.To, msg.Subject, msg.Body)

			case "send_email":
				inboxID := args["inbox_id"]
				to := args["to"]
				subject := args["subject"]
				body := args["body"]
				err := am.SendEmail(inboxID, to, subject, body)
				if err != nil {
					return tools.Result{Output: "Error: " + err.Error()}, nil
				}
				output = "Email sent successfully"

			case "wait_for_email":
				inboxID := args["inbox_id"]
				subject := args["subject"]
				timeout := 120
				if t, ok := args["timeout"]; ok {
					fmt.Sscanf(t, "%d", &timeout)
				}
				msg, err := am.WaitForEmail(inboxID, subject, time.Duration(timeout)*time.Second)
				if err != nil {
					return tools.Result{Output: "Error: " + err.Error()}, nil
				}
				output = fmt.Sprintf("From: %s\nSubject: %s\n\n%s", msg.From, msg.Subject, msg.Body)

			default:
				output = "Unknown action. Use: list_inboxes, create_inbox, get_inbox, list_messages, get_message, send_email, wait_for_email"
			}

			return tools.Result{Output: output}, nil
		},
	})
}
