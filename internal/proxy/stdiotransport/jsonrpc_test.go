package stdiotransport

import (
	"encoding/json"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestParseMessage(t *testing.T) {
	for _, tc := range []struct {
		name      string
		raw       string
		expected  message
		wantError bool
	}{
		{
			name: "request",
			raw:  `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`,
			expected: message{
				Line:   []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`),
				Method: "tools/list",
				Key:    "n:1",
			},
		},
		{
			name: "request with a string id",
			raw:  `{"jsonrpc":"2.0","id":"abc","method":"tools/list"}`,
			expected: message{
				Line:   []byte(`{"jsonrpc":"2.0","id":"abc","method":"tools/list"}`),
				Method: "tools/list",
				Key:    "s:abc",
			},
		},
		{
			name: "notification",
			raw:  `{"jsonrpc":"2.0","method":"notifications/initialized"}`,
			expected: message{
				Line:   []byte(`{"jsonrpc":"2.0","method":"notifications/initialized"}`),
				Method: "notifications/initialized",
			},
		},
		{
			name: "response",
			raw:  `{"jsonrpc":"2.0","id":2,"result":{"ok":true}}`,
			expected: message{
				Line: []byte(`{"jsonrpc":"2.0","id":2,"result":{"ok":true}}`),
				Key:  "n:2",
			},
		},
		{
			name: "pretty printed input compacts to one line",
			raw:  "{\n  \"jsonrpc\": \"2.0\",\n  \"id\": 3,\n  \"method\": \"ping\"\n}",
			expected: message{
				Line:   []byte(`{"jsonrpc":"2.0","id":3,"method":"ping"}`),
				Method: "ping",
				Key:    "n:3",
			},
		},
		{
			name:      "null id is not a correlatable request",
			raw:       `{"jsonrpc":"2.0","id":null,"method":"ping"}`,
			expected:  message{Line: []byte(`{"jsonrpc":"2.0","id":null,"method":"ping"}`), Method: "ping"},
			wantError: false,
		},
		{
			name:      "missing jsonrpc version",
			raw:       `{"id":1,"method":"ping"}`,
			wantError: true,
		},
		{
			name:      "batch",
			raw:       `[{"jsonrpc":"2.0","id":1,"method":"ping"}]`,
			wantError: true,
		},
		{
			name:      "truncated",
			raw:       `{"jsonrpc":"2.0",`,
			wantError: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseMessage([]byte(tc.raw))
			if tc.wantError {
				if err == nil {
					t.Fatalf("expected an error, got %+v", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if diff := cmp.Diff(tc.expected, got); diff != "" {
				t.Errorf("unexpected message (-want +got):\n%s", diff)
			}
		})
	}
}

func TestMessageClassification(t *testing.T) {
	for _, tc := range []struct {
		name       string
		raw        string
		isRequest  bool
		isResponse bool
	}{
		{
			name:      "request",
			raw:       `{"jsonrpc":"2.0","id":1,"method":"ping"}`,
			isRequest: true,
		},
		{
			name: "notification",
			raw:  `{"jsonrpc":"2.0","method":"notifications/progress"}`,
		},
		{
			name:       "result",
			raw:        `{"jsonrpc":"2.0","id":1,"result":{}}`,
			isResponse: true,
		},
		{
			name:       "error",
			raw:        `{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"no such method"}}`,
			isResponse: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			msg, err := parseMessage([]byte(tc.raw))
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if msg.IsRequest() != tc.isRequest {
				t.Errorf("IsRequest: expected %v", tc.isRequest)
			}
			if msg.IsResponse() != tc.isResponse {
				t.Errorf("IsResponse: expected %v", tc.isResponse)
			}
		})
	}
}

func TestCorrelationKey(t *testing.T) {
	for _, tc := range []struct {
		name     string
		id       string
		expected string
	}{
		{
			name:     "number",
			id:       `42`,
			expected: "n:42",
		},
		{
			name:     "string",
			id:       `"42"`,
			expected: "s:42",
		},
		{
			// A string id and the number that prints the same are distinct
			// requests, so their keys must not collide.
			name:     "large number keeps its exact text",
			id:       `9007199254740993`,
			expected: "n:9007199254740993",
		},
		{
			name:     "null",
			id:       `null`,
			expected: "",
		},
		{
			name:     "absent",
			id:       ``,
			expected: "",
		},
		{
			name:     "structured",
			id:       `{"nested":true}`,
			expected: "",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := correlationKey(json.RawMessage(tc.id)); got != tc.expected {
				t.Errorf("expected %q, got %q", tc.expected, got)
			}
		})
	}
}
