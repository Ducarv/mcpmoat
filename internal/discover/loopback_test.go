package discover_test

import (
	"fmt"
	"testing"

	"github.com/Ducarv/mcpmoat/internal/discover"
)

func TestIsLoopbackHost(t *testing.T) {
	t.Parallel()

	tests := []struct {
		host string
		want bool
	}{
		{host: "localhost", want: true},
		// Go sends these through HTTP_PROXY: its bypass is case sensitive.
		{host: "LOCALHOST", want: false},
		{host: "LocalHost", want: false},
		{host: "127.0.0.1", want: true},
		{host: "127.0.0.2", want: true},
		{host: "127.255.255.254", want: true},
		{host: "::1", want: true},
		{host: "0:0:0:0:0:0:0:1", want: true},
		{host: "::ffff:127.0.0.1", want: true},
		{host: "::1%lo0", want: true},

		// Not loopback.
		{host: "fe80::1%en0", want: false},
		{host: "10.0.0.1", want: false},
		{host: "128.0.0.1", want: false},
		{host: "126.255.255.255", want: false},
		{host: "0.0.0.0", want: false},
		{host: "::", want: false},
		{host: "::ffff:10.0.0.1", want: false},
		{host: "example.com", want: false},
		// DNS names can point anywhere, even when they look local.
		{host: "localhost.example.com", want: false},
		{host: "127.0.0.1.nip.io", want: false},
		{host: "localhost.", want: false},
		{host: " localhost", want: false},
		// Short IPv4 forms do not parse as an address, so they get the
		// warning. That is the safe side.
		{host: "127.1", want: false},
		// The caller passes url.URL.Hostname, which has no brackets.
		{host: "[::1]", want: false},
		{host: "", want: false},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("%q", tt.host), func(t *testing.T) {
			t.Parallel()
			if got := discover.IsLoopbackHost(tt.host); got != tt.want {
				t.Errorf("IsLoopbackHost(%q) = %t, want %t", tt.host, got, tt.want)
			}
		})
	}
}
