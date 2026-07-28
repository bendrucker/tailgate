package router

import (
	"errors"
	"net/http"
	"runtime/debug"
)

// responseRecorder observes the response on its way out. It reports whether
// anything has been committed, which is what lets panic recovery decide
// between writing a 500 and abandoning a response already in flight, and it
// exposes the status and headers the transport produced so the router can bind
// a minted session to its identity.
type responseRecorder struct {
	http.ResponseWriter

	// onHeader runs once, with the status and headers about to be sent.
	onHeader    func(status int, header http.Header)
	wroteHeader bool
}

func newResponseRecorder(w http.ResponseWriter) *responseRecorder {
	return &responseRecorder{ResponseWriter: w}
}

func (rec *responseRecorder) WriteHeader(status int) {
	// ReverseProxy forwards an upstream's 1xx by calling WriteHeader with the
	// interim status. The real response still follows, so an interim must not
	// latch the recorder or consume the one-shot header callback.
	if status < http.StatusOK {
		rec.ResponseWriter.WriteHeader(status)
		return
	}
	if rec.wroteHeader {
		return
	}
	rec.wroteHeader = true
	if rec.onHeader != nil {
		rec.onHeader(status, rec.Header())
	}
	rec.ResponseWriter.WriteHeader(status)
}

func (rec *responseRecorder) Write(b []byte) (int, error) {
	if !rec.wroteHeader {
		rec.WriteHeader(http.StatusOK)
	}
	return rec.ResponseWriter.Write(b)
}

// Flush forwards to the underlying writer so SSE events reach the client as
// the transport produces them.
func (rec *responseRecorder) Flush() {
	if !rec.wroteHeader {
		rec.WriteHeader(http.StatusOK)
	}
	// A writer that cannot flush has nothing buffered to lose.
	_ = http.NewResponseController(rec.ResponseWriter).Flush()
}

// Unwrap exposes the underlying writer to http.ResponseController, so a
// transport can still set deadlines and hijack through the wrapper.
func (rec *responseRecorder) Unwrap() http.ResponseWriter { return rec.ResponseWriter }

// recoverPanic turns a panic in the request path into a 500. A panic partway
// through a response cannot be un-sent, so the status is only written when
// nothing has been committed yet.
func (rt *Router) recoverPanic(rec *responseRecorder, r *http.Request) {
	recovered := recover()
	if recovered == nil {
		return
	}
	if err, ok := recovered.(error); ok && errors.Is(err, http.ErrAbortHandler) {
		panic(recovered)
	}
	rt.logger.Error("panic serving request",
		"method", r.Method,
		"path", r.URL.EscapedPath(),
		"panic", recovered,
		"stack", string(debug.Stack()),
	)
	if !rec.wroteHeader {
		http.Error(rec, "internal server error", http.StatusInternalServerError)
	}
}
