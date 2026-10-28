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
		{name: "passcode", want: true},
		{name: "PASS_CODE", want: true},
		{name: "userPasscode", want: true},
		{name: "ACCESS_CODE", want: true},
		{name: "access-code", want: true},
		{name: "accessCode", want: true},
		{name: "accesscode", want: true},
		{name: "SIGNATURE", want: true},
		{name: "webhookSignature", want: true},
		{name: "x-hub-signature-256", want: true},
		{name: "X_HMAC", want: true},
		{name: "hmacKey", want: true},
		{name: "X-Hmac-Sha256", want: true},
		// Accepted false positives: the name holds a secret word but is
		// not a credential name.
		{name: "SIGNATURE_ALGORITHM", want: true},
		{name: "ACCESS_CODE_LENGTH", want: true},

		// Short forms match as a whole word, or at the end of an all-caps word.
		{name: "pass", want: true},
		{name: "DB_PASS", want: true},
		{name: "PGPASS", want: true},
		{name: "--pass2", want: true},
		{name: "jwt", want: true},
		{name: "githubPat", want: true},
		{name: "pin", want: true},
		{name: "OTP", want: true},
		{name: "salt", want: true},
		{name: "SIGNING_SALT", want: true},
		{name: "passwordSalt", want: true},
		{name: "--salt2", want: true},
		{name: "PWSALT", want: true},
		{name: "seed", want: true},
		{name: "APP_SEED", want: true},
		{name: "--seed", want: true},
		{name: "seedPhrase", want: true},
		{name: "SEED_PHRASE", want: true},
		{name: "walletSeed", want: true},
		{name: "SEED2", want: true},
		{name: "WALLETSEED", want: true},
		{name: "pepper", want: true},
		{name: "PASSWORD_PEPPER", want: true},
		{name: "hashPepper", want: true},
		{name: "APPPEPPER", want: true},

		// An all-caps word that starts with "PASS" matches.
		{name: "PASSCODE", want: true},
		{name: "DB_PASSWRD", want: true},
		{name: "PASSCODE1", want: true},
		// Accepted false positives of the all-caps rules.
		{name: "PASSIVE_MODE", want: true},
		{name: "PASSTHROUGH", want: true},
		{name: "SALT_ROUNDS", want: true},
		{name: "BASALT", want: true},
		// Accepted false positives of "seed": a random seed is no secret,
		// and an all-caps word can end in "SEED".
		{name: "RANDOM_SEED", want: true},
		{name: "randomSeed", want: true},
		{name: "LINSEED", want: true},

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
		{name: "passive", want: false},
		{name: "passthrough", want: false},
		{name: "salty", want: false},
		{name: "SALTY_DOG_ENABLED", want: false},
		{name: "basalt", want: false},
		{name: "signing", want: false},
		{name: "SIGNING_METHOD", want: false},
		{name: "ACCESS_LEVEL", want: false},
		{name: "access", want: false},
		{name: "ERROR_CODE", want: false},
		{name: "SUCCESS_CODE", want: false},
		{name: "--assignee", want: false},
		{name: "--license", want: false},
		{name: "LICENSE", want: false},
		{name: "seedling", want: false},
		{name: "linseed", want: false},
		{name: "--seeds", want: false},
		{name: "SEEDS", want: false},
		{name: "peppermint", want: false},
		{name: "PEPPERONI", want: false},
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
