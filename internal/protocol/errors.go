package protocol

import (
	"encoding/json"
	"errors"
	"net/http"
)

// JSON-RPC error codes this revision defines, allocated from the -32020 to
// -32099 sub-range the MCP specification reserves for itself.
const (
	// CodeUnsupportedProtocolVersion reports a revision the server does not
	// implement. Its data carries the revisions it does.
	CodeUnsupportedProtocolVersion = -32022
)

// errorResponse is a JSON-RPC error response. The id is always null: every
// error tailgate originates is a refusal of a message it declined to act on,
// and it does not claim to have read an id out of a body it rejected.
type errorResponse struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      *string     `json:"id"`
	Error   errorObject `json:"error"`
}

type errorObject struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

// WriteError answers with an HTTP status and a JSON-RPC error body.
//
// The body is what keeps a 2026-07-28 client from misreading the refusal. A
// client probing for the server's era falls back to the legacy initialize
// handshake on a 400 whose body is not a recognized JSON-RPC error, so an
// intermediary that refuses a modern request with bare text talks its callers
// into downgrading. tailgate answers in the modern shape so a rejected request
// reads as a rejected request.
func WriteError(w http.ResponseWriter, status, code int, message string, data any) {
	body, err := json.Marshal(errorResponse{
		JSONRPC: "2.0",
		Error:   errorObject{Code: code, Message: message, Data: data},
	})
	if err != nil {
		http.Error(w, http.StatusText(status), status)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

// WriteUnsupportedVersion refuses a revision tailgate does not speak, naming
// the ones it does so the client can retry rather than guess.
func WriteUnsupportedVersion(w http.ResponseWriter, requested string) {
	WriteError(w, http.StatusBadRequest, CodeUnsupportedProtocolVersion,
		"Unsupported MCP-Protocol-Version: "+requested,
		map[string]any{"supported": Supported})
}

// WriteHeaderMismatch refuses a request whose mirrored headers disagree with
// its body. The response names the header at fault and nothing else: the
// detail on err quotes caller-supplied values, which belong in the log rather
// than on an internet-facing response.
func WriteHeaderMismatch(w http.ResponseWriter, err error) {
	message := "Header mismatch"
	var mismatch *HeaderError
	if errors.As(err, &mismatch) && mismatch.Header != "" {
		message += ": " + mismatch.Header + " does not match the request body"
	}
	WriteError(w, http.StatusBadRequest, CodeHeaderMismatch, message, nil)
}
