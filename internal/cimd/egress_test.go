package cimd

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
)

func TestAllowedAddr(t *testing.T) {
	for _, tc := range []struct {
		name string
		addr string
		want bool
	}{
		{name: "public ipv4", addr: "93.184.216.34", want: true},
		{name: "public ipv6", addr: "2606:2800:220:1:248:1893:25c8:1946", want: true},
		{name: "loopback ipv4", addr: "127.0.0.1"},
		{name: "loopback ipv6", addr: "::1"},
		{name: "rfc 1918 ten", addr: "10.1.2.3"},
		{name: "rfc 1918 one seven two", addr: "172.16.5.5"},
		{name: "rfc 1918 one nine two", addr: "192.168.1.1"},
		{name: "link local ipv4", addr: "169.254.169.254"},
		{name: "link local ipv6", addr: "fe80::1"},
		{name: "unspecified ipv4", addr: "0.0.0.0"},
		{name: "this network", addr: "0.0.0.1"},
		{name: "ipv4 mapped this network", addr: "::ffff:0.1.2.3"},
		{name: "unspecified ipv6", addr: "::"},
		{name: "multicast", addr: "224.0.0.1"},
		{name: "broadcast", addr: "255.255.255.255"},
		{name: "tailscale cgnat", addr: "100.100.100.100"},
		{name: "cgnat range edge", addr: "100.127.255.255"},
		{name: "just past cgnat", addr: "100.128.0.1", want: true},
		{name: "tailscale ula", addr: "fd7a:115c:a1e0::1"},
		{name: "other ula", addr: "fd12:3456::1"},
		{name: "ipv4 mapped loopback", addr: "::ffff:127.0.0.1"},
		{name: "ipv4 mapped private", addr: "::ffff:10.0.0.1"},
		{name: "ipv4 mapped cgnat", addr: "::ffff:100.64.0.1"},
		{name: "ipv4 mapped public", addr: "::ffff:93.184.216.34", want: true},
		{name: "invalid", addr: ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var addr netip.Addr
			if tc.addr != "" {
				addr = netip.MustParseAddr(tc.addr)
			}
			if got := allowedAddr(addr); got != tc.want {
				t.Errorf("allowedAddr(%q) = %v, want %v", tc.addr, got, tc.want)
			}
		})
	}
}

// The guard runs inside the dialer, so a request to a loopback origin must
// fail before any bytes are sent.
func TestClientRefusesLoopback(t *testing.T) {
	var hits int
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits++ }))
	t.Cleanup(server.Close)

	_, err := NewClient().Get(server.URL + "/client")
	if !errors.Is(err, ErrForbiddenAddress) {
		t.Fatalf("Get = %v, want %v", err, ErrForbiddenAddress)
	}
	if hits != 0 {
		t.Errorf("the origin was reached %d times", hits)
	}
}

func TestClientFollowsNoRedirects(t *testing.T) {
	client := NewClient()
	if client.CheckRedirect == nil {
		t.Fatal("client follows redirects")
	}
	if err := client.CheckRedirect(nil, nil); !errors.Is(err, http.ErrUseLastResponse) {
		t.Errorf("CheckRedirect = %v, want %v", err, http.ErrUseLastResponse)
	}
	if client.Timeout != fetchTimeout {
		t.Errorf("Timeout = %v, want %v", client.Timeout, fetchTimeout)
	}
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("Transport is %T", client.Transport)
	}
	if transport.Proxy != nil {
		t.Error("transport uses a proxy")
	}
}
