package tsnetserver

import (
	"errors"
	"net/netip"
	"strings"
	"testing"
)

func TestWhoIsRefusals(t *testing.T) {
	localErr := errors.New("local client unavailable")
	for _, tc := range []struct {
		name   string
		node   *fakeNode
		closed bool
		peer   netip.AddrPort
		want   error
		reason string
	}{
		{
			name:   "no peer address",
			node:   &fakeNode{},
			reason: "no peer address",
		},
		{
			name:   "after close",
			node:   &fakeNode{},
			closed: true,
			peer:   netip.MustParseAddrPort("100.101.102.103:52000"),
			want:   ErrClosed,
		},
		{
			name: "local client unavailable",
			node: &fakeNode{localErr: localErr},
			peer: netip.MustParseAddrPort("100.101.102.103:52000"),
			want: localErr,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := newServer(tc.node, 443)
			if tc.closed {
				if err := srv.Close(); err != nil {
					t.Fatalf("Close = %v", err)
				}
			}
			_, err := srv.WhoIs(t.Context(), tc.peer)
			if err == nil {
				t.Fatal("WhoIs succeeded")
			}
			if tc.want != nil && !errors.Is(err, tc.want) {
				t.Errorf("WhoIs error = %v, want %v", err, tc.want)
			}
			if tc.reason != "" && !strings.Contains(err.Error(), tc.reason) {
				t.Errorf("WhoIs error = %q, want it to name %q", err, tc.reason)
			}
		})
	}
}
