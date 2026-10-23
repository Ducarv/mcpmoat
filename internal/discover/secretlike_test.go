package discover_test

import (
	"fmt"
	"testing"

	"github.com/Ducarv/mcpmoat/internal/discover"
)

func TestHasTokenPrefix(t *testing.T) {
	t.Parallel()

	tests := []struct {
		s    string
		want bool
	}{
		// Every known prefix, with fake text after it.
		{s: "sk-fake1234", want: true},
		{s: "sk_fake1234", want: true},
		{s: "pk_fake1234", want: true},
		{s: "rk_fake1234", want: true},
		{s: "ghp_fake1234", want: true},
		{s: "gho_fake1234", want: true},
		{s: "ghu_fake1234", want: true},
		{s: "ghs_fake1234", want: true},
		{s: "github_pat_fake1234", want: true},
		{s: "glpat-fake1234", want: true},
		{s: "xoxb-fake1234", want: true},
		{s: "AKIAFAKEFAKE", want: true},
		{s: "AIzaFakeFake", want: true},
		{s: "eyJfakefake", want: true},

		// The match ignores case.
		{s: "GHP_FAKE1234", want: true},
		{s: "Sk-Fake1234", want: true},
		{s: "akiafakefake", want: true},

		// The prefix alone, or a shorter text, is not a match: some text must follow.
		{s: "sk-", want: false},
		{s: "ghp_", want: false},
		{s: "github_pat_", want: false},
		{s: "xox", want: false},
		{s: "sk", want: false},
		{s: "s", want: false},

		// The prefix must be at the start.
		{s: " sk-fake1234", want: false},
		{s: "my-sk-fake1234", want: false},
		{s: "Bearer ghp_fake1234", want: false},

		// Plain text.
		{s: "hello", want: false},
		{s: "skate", want: false},
		{s: "github", want: false},
		{s: "", want: false},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("%q", tt.s), func(t *testing.T) {
			t.Parallel()
			if got := discover.HasTokenPrefix(tt.s); got != tt.want {
				t.Errorf("HasTokenPrefix(%q) = %t, want %t", tt.s, got, tt.want)
			}
		})
	}
}

func TestIsSecretName(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		want bool
	}{
		// Words that match anywhere in the name.
		{name: "API_KEY", want: true},
		{name: "api-key", want: true},
		{name: "apiKey", want: true},
		{name: "X-Api-Key", want: true},
		{name: "GITHUB_TOKEN", want: true},
		{name: "githubtoken", want: true},
		{name: "clientSecret", want: true},
		{name: "password", want: true},
		{name: "DB_PASSWORD", want: true},
		{name: "Authorization", want: true},
		{name: "Cookie", want: true},
		{name: "SESSION_ID", want: true},
		{name: "AWS_CREDENTIALS", want: true},

		// Short forms match as a whole word, or at the end of an all-caps word.
		{name: "pass", want: true},
		{name: "DB_PASS", want: true},
		{name: "PGPASS", want: true},
		{name: "--pass2", want: true},
		{name: "jwt", want: true},
		{name: "githubPat", want: true},
		{name: "pin", want: true},
		{name: "OTP", want: true},

		// Not secret names.
		{name: "LOG_LEVEL", want: false},
		{name: "PATH", want: false},
		{name: "HOME", want: false},
		{name: "bypass", want: false},
		{name: "compass", want: false},
		{name: "path", want: false},
		{name: "patch", want: false},
		{name: "pattern", want: false},
		{name: "spin", want: false},
		{name: "pinned", want: false},
		{name: "credit", want: false},
		{name: "Content-Type", want: false},
		{name: "", want: false},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("%q", tt.name), func(t *testing.T) {
			t.Parallel()
			if got := discover.IsSecretName(tt.name); got != tt.want {
				t.Errorf("IsSecretName(%q) = %t, want %t", tt.name, got, tt.want)
			}
		})
	}
}
