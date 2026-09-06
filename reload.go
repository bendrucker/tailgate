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
	logger *slog.Logger

	// reloading serializes Reload, so two signals in quick succession build
	// two routers in order. It also guards stopped and build.
	reloading sync.Mutex
	// build is set by start, which is also what puts the first router in
	// service.
	build func(*config.Config) (served, error)
	// stopped is set by Shutdown and Close. A signal that lands during
	// shutdown must not swap in a router nothing will ever drain.
	stopped bool
	router  atomic.Pointer[served]
	// retiring counts routers draining in the background, so shutdown waits
	// for them.
	retiring sync.WaitGroup
}

// newReloader returns a reloader serving nothing yet. The authorization server
// reaches the current router through it, and the router is built with that
// authorization server, so the reloader has to exist before either of them:
// start closes the loop by taking the build and running it.
//
// node is the section of the configuration fixed for the life of the process,
// since the tailnet node it configures is joined once.
func newReloader(path string, node config.Node, logger *slog.Logger) *reloader {
	return &reloader{path: path, node: node, logger: logger}
}

// start puts the first router in service, built from cfg, which the caller
// already loaded from path. Until it succeeds the reloader answers as what it
// is: a process with nothing to serve.
func (r *reloader) start(cfg *config.Config, build func(*config.Config) (served, error)) error {
	r.reloading.Lock()
	defer r.reloading.Unlock()

	current, err := build(cfg)
	if err != nil {
		return err
	}
	r.build = build
	r.router.Store(&current)
	return nil
}

// current is the router in service, or nil before start has put one there.
func (r *reloader) current() served {
	if rt := r.router.Load(); rt != nil {
		return *rt
	}
	return nil
}

// A request in flight on the previous router finishes there, since the swap
// replaces the pointer and never the router a handler already entered.
func (r *reloader) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	current := r.current()
	if current == nil {
		http.Error(w, "tailgate is starting", http.StatusServiceUnavailable)
		return
	}
	current.ServeHTTP(w, req)
}

// The authorization server consults HasUpstream per request, so a resource
// added by a reload is authorizable as soon as the swap lands and a removed
// one no longer is. Nothing is, before there is a router to serve it.
func (r *reloader) HasUpstream(name string) bool {
	current := r.current()
	return current != nil && current.HasUpstream(name)
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
	if r.build == nil {
		return r.refuse(fmt.Errorf("reload: nothing is serving yet"))
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

	previous := r.router.Swap(&next)
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
//
// drainTimeout is the only clock here. The second clock shutdown runs, which
// covers connections no transport ever saw, has nothing to bound during a
// reload: those connections belong to the one HTTP server, which a reload
// never replaces and which goes on serving them through the swap.
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
	var err error
	if current := r.stop(); current != nil {
		err = current.Shutdown(ctx)
	}
	r.retiring.Wait()
	return err
}

func (r *reloader) Close() error {
	current := r.stop()
	r.retiring.Wait()
	if current == nil {
		return nil
	}
	return current.Close()
}

// stop marks the reloader stopped and returns the router that is current at
// that moment, which is the last one there will be. It is nil when a startup
// failure tears the process down before start put one in service.
func (r *reloader) stop() served {
	r.reloading.Lock()
	defer r.reloading.Unlock()
	r.stopped = true
	return r.current()
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
