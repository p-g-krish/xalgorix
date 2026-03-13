package llm

import (
	"testing"
)

func TestParseAllFormats(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		wantFn string
		wantP  map[string]string
	}{
		{
			"standard equals",
			"<function=terminal_execute>\n<parameter=command>curl -I https://example.com</parameter>\n</function>",
			"terminal_execute",
			map[string]string{"command": "curl -I https://example.com"},
		},
		{
			"space variant",
			"<function=terminal_execute>\n<parameter command>curl -I https://example.com</parameter>\n</function>",
			"terminal_execute",
			map[string]string{"command": "curl -I https://example.com"},
		},
		{
			"name attr variant",
			"<function=python_action>\n<parameter name=\"code\">print(1)</parameter>\n</function>",
			"python_action",
			map[string]string{"code": "print(1)"},
		},
		{
			"finish space",
			"<function=finish>\n<parameter summary>assessment done</parameter>\n</function>",
			"finish",
			map[string]string{"summary": "assessment done"},
		},
		{
			"multi-line value",
			"<function=finish>\n<parameter=summary>line1\nline2\nline3</parameter>\n</function>",
			"finish",
			map[string]string{"summary": "line1\nline2\nline3"},
		},
		{
			"list_files space",
			"<function=list_files>\n<parameter path>/var/www</parameter>\n</function>",
			"list_files",
			map[string]string{"path": "/var/www"},
		},
		{
			"send_request multi space",
			"<function=send_request>\n<parameter method>GET</parameter>\n<parameter url>https://example.com</parameter>\n</function>",
			"send_request",
			map[string]string{"method": "GET", "url": "https://example.com"},
		},
		{
			"multi-line space value",
			"<function=finish>\n<parameter summary>line one\nline two\nline three</parameter>\n</function>",
			"finish",
			map[string]string{"summary": "line one\nline two\nline three"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			calls := ParseToolCalls(tt.input)
			if len(calls) == 0 {
				t.Fatalf("no tool calls parsed")
			}
			if calls[0].Name != tt.wantFn {
				t.Errorf("fn = %q, want %q", calls[0].Name, tt.wantFn)
			}
			for k, v := range tt.wantP {
				got, ok := calls[0].Args[k]
				if !ok {
					t.Errorf("missing param %q (args=%v)", k, calls[0].Args)
				} else if got != v {
					t.Errorf("param[%s] = %q, want %q", k, got, v)
				}
			}
		})
	}
}
