package stdiotransport

import (
	"bytes"
	"encoding/json"
	"errors"
)

const jsonrpcVersion = "2.0"

// errInvalidMessage rejects anything that is not a single well-formed JSON-RPC
// 2.0 message. MCP 2025-11-25 removed batching, so an array body is invalid
// rather than a list to unpack.
var errInvalidMessage = errors.New("stdiotransport: invalid JSON-RPC message")

// message is one parsed JSON-RPC message. Line is the compacted form, since
// the child's pipes are newline-delimited and a pretty-printed body would
// otherwise frame as several messages.
type message struct {
	Line   []byte
	Method string
	// Key correlates a response to the request that is waiting for it. It is
	// empty when the message carries no usable id, which is how a notification
	// is told from a request.
	Key string
}

func parseMessage(raw []byte) (message, error) {
	var envelope struct {
		JSONRPC string          `json:"jsonrpc"`
		Method  string          `json:"method"`
		ID      json.RawMessage `json:"id"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return message{}, errInvalidMessage
	}
	if envelope.JSONRPC != jsonrpcVersion {
		return message{}, errInvalidMessage
	}
	var line bytes.Buffer
	if err := json.Compact(&line, raw); err != nil {
		return message{}, errInvalidMessage
	}
	return message{
		Line:   line.Bytes(),
		Method: envelope.Method,
		Key:    correlationKey(envelope.ID),
	}, nil
}

// IsRequest reports whether the message expects a response.
func (m message) IsRequest() bool { return m.Method != "" && m.Key != "" }

// IsResponse reports whether the message answers a request.
func (m message) IsResponse() bool { return m.Method == "" && m.Key != "" }

// correlationKey renders a JSON-RPC id as a map key. JSON-RPC ids are strings
// or numbers, and the type is part of the identity, so 1 and "1" are distinct
// requests. Numbers keep their decoded text rather than a float round trip, so
// an id too large for float64 still correlates. Anything else (null, absent, a
// structured value) yields no key.
func correlationKey(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var id any
	if err := decoder.Decode(&id); err != nil {
		return ""
	}
	switch id := id.(type) {
	case string:
		return "s:" + id
	case json.Number:
		return "n:" + id.String()
	default:
		return ""
	}
}
