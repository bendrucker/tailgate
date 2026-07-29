package tsnetserver

import (
	"errors"
	"log/slog"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestOpenerUserLogf(t *testing.T) {
	authURL := "https://login.tailscale.com/a/0123456789abcdef"

	for _, tc := range []struct {
		name     string
		messages []string
		opened   []string
	}{
		{
			name:     "login url is opened",
			messages: []string{"To start this tsnet server, restart with TS_AUTHKEY set, or go to: " + authURL},
			opened:   []string{authURL},
		},
		{
			name: "reprinted url is opened once",
			// printAuthURLLoop reprints the same URL every few seconds until
			// the node joins, and each reprint must not open another tab.
			messages: []string{
				"To start this tsnet server, restart with TS_AUTHKEY set, or go to: " + authURL,
				"To start this tsnet server, restart with TS_AUTHKEY set, or go to: " + authURL,
			},
			opened: []string{authURL},
		},
		{
			name:     "unrelated message opens nothing",
			messages: []string{"tsnet running state path /var/lib/tailgate/tailscaled.state"},
		},
		{
			name:     "url elsewhere in the message is opened",
			messages: []string{"go to: " + authURL + " to authorize"},
			opened:   []string{authURL},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var opened, logged []string
			o := &opener{
				open:   func(url string) error { opened = append(opened, url); return nil },
				logger: discardLogger(),
			}
			logf := o.userLogf(func(format string, args ...any) { logged = append(logged, format) })

			for _, message := range tc.messages {
				logf("%s", message)
			}

			if diff := cmp.Diff(tc.opened, opened); diff != "" {
				t.Errorf("opened URLs differ:\n%s", diff)
			}
			if len(logged) != len(tc.messages) {
				t.Errorf("expected %d messages logged, got %d", len(tc.messages), len(logged))
			}
		})
	}
}

func TestOpenerFailureStillLogs(t *testing.T) {
	var logged int
	o := &opener{
		open:   func(string) error { return errors.New("no browser") },
		logger: discardLogger(),
	}
	logf := o.userLogf(func(string, ...any) { logged++ })

	logf("go to: %s", "https://login.tailscale.com/a/abc")

	if logged != 1 {
		t.Errorf("expected the message to reach the logger, got %d", logged)
	}
}

func discardLogger() *slog.Logger {
	return slog.New(slog.DiscardHandler)
}
