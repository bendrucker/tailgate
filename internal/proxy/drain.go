package proxy

import (
	"context"
	"sync"
)

// Drain implements the seam's shutdown contract for a Transport: refuse new
// requests once shutdown begins, wait for in-flight requests and open streams,
// and abandon what remains on Close. Transports hold one and delegate their
// Shutdown and Close to it so every adapter drains identically.
//
// The zero value is ready to use.
type Drain struct {
	inflight sync.WaitGroup

	mu       sync.Mutex
	draining bool
	nextID   uint64
	cancels  map[uint64]context.CancelCauseFunc
}

// InFlight is one registered request. Deferring Done releases it from the
// drain.
type InFlight struct {
	drain  *Drain
	id     uint64
	ctx    context.Context
	cancel context.CancelCauseFunc
	once   sync.Once
}

// Enter registers a request and returns its handle. It returns ErrDraining
// once shutdown has begun, which the caller must answer with 503 rather than
// starting work.
func (d *Drain) Enter(ctx context.Context) (*InFlight, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.draining {
		return nil, ErrDraining
	}
	if d.cancels == nil {
		d.cancels = make(map[uint64]context.CancelCauseFunc)
	}
	reqCtx, cancel := context.WithCancelCause(ctx)
	id := d.nextID
	d.nextID++
	d.cancels[id] = cancel
	d.inflight.Add(1)
	return &InFlight{drain: d, id: id, ctx: reqCtx, cancel: cancel}, nil
}

// Context returns the request context. It is canceled when the request
// finishes, when its own deadline fires via Cancel, or when Close abandons the
// request with cause ErrDraining.
func (f *InFlight) Context() context.Context { return f.ctx }

// Cancel cancels the request context with cause, which handlers recover with
// context.Cause to distinguish a timeout from a client hangup.
func (f *InFlight) Cancel(cause error) { f.cancel(cause) }

// Done releases the request. Repeat calls are no-ops.
func (f *InFlight) Done() {
	f.once.Do(func() {
		f.cancel(nil)
		f.drain.mu.Lock()
		delete(f.drain.cancels, f.id)
		f.drain.mu.Unlock()
		f.drain.inflight.Done()
	})
}

// Shutdown refuses new requests, then waits for the in-flight ones to finish
// or ctx to expire. On expiry the remainder is left for Close.
func (d *Drain) Shutdown(ctx context.Context) error {
	d.mu.Lock()
	d.draining = true
	d.mu.Unlock()

	done := make(chan struct{})
	go func() {
		d.inflight.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Close refuses new requests, cancels every in-flight request with cause
// ErrDraining, and returns once they have all released. It is safe after
// Shutdown and safe to call repeatedly.
func (d *Drain) Close() {
	d.mu.Lock()
	d.draining = true
	cancels := make([]context.CancelCauseFunc, 0, len(d.cancels))
	for _, cancel := range d.cancels {
		cancels = append(cancels, cancel)
	}
	d.mu.Unlock()

	for _, cancel := range cancels {
		cancel(ErrDraining)
	}
	d.inflight.Wait()
}
