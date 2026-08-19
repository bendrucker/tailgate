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
	// ID is the id exactly as the sender wrote it, kept so a rewritten message
	// can be restored to the form its sender will recognize.
	ID json.RawMessage
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
		ID:     envelope.ID,
		Key:    correlationKey(envelope.ID),
	}, nil
}

// IsRequest reports whether the message expects a response.
func (m message) IsRequest() bool { return m.Method != "" && m.Key != "" }

// IsResponse reports whether the message answers a request.
func (m message) IsResponse() bool { return m.Method == "" && m.Key != "" }

// IsNotification reports whether the message is a one-way message from the
// child, which under a stateless revision is what a subscription stream
// carries. JSON-RPC tells a notification from a request by the absence of the
// id member, not by whether the id it carries is usable, so an id that
// correlates to nothing does not turn a request into one.
func (m message) IsNotification() bool { return m.Method != "" && len(m.ID) == 0 }

// WellFormed reports whether the message is one of the three shapes JSON-RPC
// defines. An id present but uncorrelatable leaves a message that is none of
// them, and passing one on would put a caller-chosen id into the child's own id
// space under a message whose answer could never be routed back.
func (m message) WellFormed() bool {
	return m.IsRequest() || m.IsResponse() || m.IsNotification()
}

// setID re-encodes a JSON-RPC message under a different id.
//
// It exists because a stateless revision gives up the shared id space a
// session used to provide: each POST stands alone, so two concurrent requests
// from one caller may both call themselves id 1. tailgate correlates on an id
// it mints per message and restores the caller's own before answering.
func setID(raw []byte, id json.RawMessage) ([]byte, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return nil, errInvalidMessage
	}
	fields["id"] = id
	rewritten, err := json.Marshal(fields)
	if err != nil {
		return nil, errInvalidMessage
	}
	return rewritten, nil
}

// errorCode reports the JSON-RPC error code a response carries, and whether it
// is an error response at all.
func errorCode(raw []byte) (int, bool) {
	var envelope struct {
		Error *struct {
			Code int `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil || envelope.Error == nil {
		return 0, false
	}
	return envelope.Error.Code, true
}

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
