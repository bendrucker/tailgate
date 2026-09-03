package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/bendrucker/tailgate/internal/config"
)

// served is what a configuration load produces and a reload replaces.
// *router.Router implements it.
type served interface {
	http.Handler
	HasUpstream(name string) bool
	// Shutdown stops accepting work and waits out in-flight requests.
	Shutdown(ctx context.Context) error
	// Close tears down whatever Shutdown left.
	Close() error
}

// reloader serves whichever router the most recent successful configuration
// load produced, and swaps in a new one on Reload without dropping the
// process. Everything a client holds across a reload lives outside the
// router: the token store, the authorization server, and the tailnet node
// are built once, so a reload changes what is served and never who may be
// served.
type reloader struct {
	path   string
	node   config.Node
	build  func(*config.Config) (served, error)
	logger *slog.Logger

	// reloading serializes Reload, so two signals in quick succession build
	// two routers in order. It also guards stopped.
	reloading sync.Mutex
	// stopped is set by Shutdown and Close. A signal that lands during
	// shutdown must not swap in a router nothing will ever drain.
	stopped bool
	current atomic.Pointer[served]
	// retiring counts routers draining in the background, so shutdown waits
	// for them.
	retiring sync.WaitGroup
}

// newReloader builds the first router from cfg, which the caller already
// loaded from path. The node section of cfg is fixed for the life of the
// process, since the tailnet node it configures is joined once.
func newReloader(path string, cfg *config.Config, build func(*config.Config) (served, error), logger *slog.Logger) (*reloader, error) {
	r := &reloader{path: path, node: cfg.Node, build: build, logger: logger}
	current, err := build(cfg)
	if err != nil {
		return nil, err
	}
	r.current.Store(&current)
	return r, nil
}

// A request in flight on the previous router finishes there, since the swap
// replaces the pointer and never the router a handler already entered.
func (r *reloader) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	(*r.current.Load()).ServeHTTP(w, req)
}

// The authorization server consults HasUpstream per request, so a resource
// added by a reload is authorizable as soon as the swap lands and a removed
// one no longer is.
func (r *reloader) HasUpstream(name string) bool {
	return (*r.current.Load()).HasUpstream(name)
}

// Reload loads the file again and swaps in a router built from it. A file
// that fails to load, a changed node section, or a router that fails to
// build is refused with the reason logged and the running router untouched:
// an operator who mistyped the file must not lose the running service.
//
// The previous router drains in the background under the same deadline
// shutdown uses. Sessions it bound do not carry over, so a stateful client
// re-initializes after its next request answers 404, which is the protocol's
// own recovery path. Tokens do carry over, because the store that holds them
// is not part of the router.
func (r *reloader) Reload() error {
	r.reloading.Lock()
	defer r.reloading.Unlock()

	if r.stopped {
		return r.refuse(fmt.Errorf("reload: the process is shutting down"))
	}
	cfg, err := config.Load(r.path)
	if err != nil {
		return r.refuse(fmt.Errorf("reload: %w", err))
	}
	if changed := nodeChanges(r.node, cfg.Node); len(changed) > 0 {
		return r.refuse(fmt.Errorf("reload: node.%s changed, which takes a restart to apply", strings.Join(changed, " and node.")))
	}
	next, err := r.build(cfg)
	if err != nil {
		return r.refuse(fmt.Errorf("reload: %w", err))
	}

	previous := r.current.Swap(&next)
	r.logger.Info("configuration reloaded", "path", r.path, "upstreams", len(cfg.Upstreams))

	r.retiring.Add(1)
	go func() {
		defer r.retiring.Done()
		r.retire(*previous)
	}()
	return nil
}

func (r *reloader) refuse(err error) error {
	r.logger.Error("reload refused, the running configuration stays in service", "path", r.path, "err", err)
	return err
}

// retire drains a replaced router and then tears it down, so a request that
// entered it before the swap finishes and a stdio child it spawned dies.
func (r *reloader) retire(previous served) {
	ctx, cancel := context.WithTimeout(context.Background(), drainTimeout)
	defer cancel()
	if err := previous.Shutdown(ctx); err != nil {
		r.logger.Warn("replaced upstreams did not drain", "err", err)
	}
	if err := previous.Close(); err != nil {
		r.logger.Warn("replaced upstreams did not close", "err", err)
	}
}

// Shutdown drains the current router and waits for any replaced router still
// draining, which is bounded by the same deadline. Reloads are refused from
// here on.
func (r *reloader) Shutdown(ctx context.Context) error {
	err := r.stop().Shutdown(ctx)
	r.retiring.Wait()
	return err
}

func (r *reloader) Close() error {
	current := r.stop()
	r.retiring.Wait()
	return current.Close()
}

// stop marks the reloader stopped and returns the router that is current at
// that moment, which is the last one there will be.
func (r *reloader) stop() served {
	r.reloading.Lock()
	defer r.reloading.Unlock()
	r.stopped = true
	return *r.current.Load()
}

// nodeChanges names the fields of the node section that differ between the
// configuration the process started with and the one just loaded, by their
// JSON keys. It walks the struct so a field added to config.Node is covered
// without being listed here, and reads the tags itself so the refusal names
// the key the operator changed, which a go-cmp diff would not.
func nodeChanges(running, loaded config.Node) []string {
	a, b := reflect.ValueOf(running), reflect.ValueOf(loaded)
	var changed []string
	for i := range a.NumField() {
		if reflect.DeepEqual(a.Field(i).Interface(), b.Field(i).Interface()) {
			continue
		}
		key, _, _ := strings.Cut(a.Type().Field(i).Tag.Get("json"), ",")
		changed = append(changed, key)
	}
	return changed
}
