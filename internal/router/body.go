package router

import (
	"bytes"
	"errors"
	"io"
	"net/http"

	"github.com/bendrucker/tailgate/internal/protocol"
)

// bodyStep caps the request body, answering 413 when the caller exceeds it,
// and leaves the buffered bytes on the exchange so the protocol step can
// inspect what will be forwarded. The body is read here rather than wrapped,
// because a limit discovered while the transport is already streaming to the
// upstream cannot be reported as a status: an MCP client request is one
// JSON-RPC message, so buffering it costs the cap at most.
type bodyStep struct{ rt *Router }

func (s bodyStep) name() string { return "body" }

func (s bodyStep) check(ex *exchange) *refusal {
	r := ex.r
	if r.Body == nil || r.Body == http.NoBody {
		return nil
	}
	if r.ContentLength > s.rt.maxBody {
		return s.tooLarge(r)
	}

	// MaxBytesReader marks the connection for close through an interface the
	// recorder does not satisfy and does not forward, so the underlying writer
	// is what gets handed over. Without it an overflowing request leaves the
	// server draining the rest of the body for keep-alive reuse.
	body, err := io.ReadAll(http.MaxBytesReader(ex.rec.Unwrap(), r.Body, s.rt.maxBody))
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			return s.tooLarge(r)
		}
		s.rt.logger.Debug("read request body", "err", err)
		return refuseProtocol(protocol.ErrorObject{
			Code:    protocol.CodeParseError,
			Message: "Could not read the request body",
		})
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	r.ContentLength = int64(len(body))
	ex.body = body
	return nil
}

func (s bodyStep) tooLarge(r *http.Request) *refusal {
	s.rt.logger.Warn("request body too large", "method", r.Method, "limit", s.rt.maxBody)
	return refuse(http.StatusRequestEntityTooLarge, "request body too large")
}
