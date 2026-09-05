package protocol

import (
	"encoding/json"
	"errors"
	"net/http"
)

// The sub-range the MCP specification reserves for the codes it defines,
// allocated sequentially from the top.
const (
	revisionCodeFirst = -32020
	revisionCodeLast  = -32099
)

// JSON-RPC error codes this revision defines, allocated from the reserved
// sub-range above.
const (
	// CodeUnsupportedProtocolVersion reports a revision the server does not
	// implement. Its data carries the revisions it does.
	CodeUnsupportedProtocolVersion = -32022
)

// The codes JSON-RPC 2.0 itself defines, for refusals that are not about a
// revision. A client probing for the server's era recognizes these too, so a
// refusal carrying one reads as a refusal rather than as an older server.
const (
	CodeParseError     = -32700
	CodeInvalidRequest = -32600
)

// IsRevisionError reports whether a JSON-RPC error code is one the MCP
// specification defines, which only a server implementing the revision can
// produce. Everything outside the reserved range is a generic JSON-RPC error
// that says nothing about which revision the peer speaks.
func IsRevisionError(code int) bool {
	return code <= revisionCodeFirst && code >= revisionCodeLast
}

// errorResponse is a JSON-RPC error response. The id is always null: every
// error tailgate originates is a refusal of a message it declined to act on,
// and it does not claim to have read an id out of a body it rejected.
type errorResponse struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      *string     `json:"id"`
	Error   ErrorObject `json:"error"`
}

// ErrorObject is the error member of a JSON-RPC error response. It is a value
// rather than a writer so a caller can decide what a refusal says before it
// decides to send it, and carry the two together.
type ErrorObject struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

// Write answers with status and the error object as the body.
//
// The body is what keeps a 2026-07-28 client from misreading the refusal. A
// client probing for the server's era falls back to the legacy initialize
// handshake on a 400 whose body is not a recognized JSON-RPC error, so an
// intermediary that refuses a modern request with bare text talks its callers
// into downgrading. tailgate answers in the modern shape so a rejected request
// reads as a rejected request.
func (e ErrorObject) Write(w http.ResponseWriter, status int) {
	body, err := json.Marshal(errorResponse{JSONRPC: "2.0", Error: e})
	if err != nil {
		http.Error(w, http.StatusText(status), status)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

// WriteError answers with an HTTP status and a JSON-RPC error body.
func WriteError(w http.ResponseWriter, status, code int, message string, data any) {
	ErrorObject{Code: code, Message: message, Data: data}.Write(w, status)
}

// UnsupportedVersion refuses a revision tailgate does not speak, naming the
// ones it does so the client can retry rather than guess.
func UnsupportedVersion(requested string) ErrorObject {
	return ErrorObject{
		Code:    CodeUnsupportedProtocolVersion,
		Message: "Unsupported MCP-Protocol-Version: " + requested,
		Data:    map[string]any{"supported": Supported},
	}
}

// WriteUnsupportedVersion answers [UnsupportedVersion] at 400.
func WriteUnsupportedVersion(w http.ResponseWriter, requested string) {
	UnsupportedVersion(requested).Write(w, http.StatusBadRequest)
}

// HeaderMismatch refuses a request whose mirrored headers disagree with its
// body. The message names the header at fault and nothing else: the detail on
// err quotes caller-supplied values, which belong in the log rather than on an
// internet-facing response.
func HeaderMismatch(err error) ErrorObject {
	message := "Header mismatch"
	var mismatch *HeaderError
	if errors.As(err, &mismatch) && mismatch.Header != "" {
		message += ": " + mismatch.Header + " does not match the request body"
	}
	return ErrorObject{Code: CodeHeaderMismatch, Message: message}
}
