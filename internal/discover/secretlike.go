package discover

// This file exports two small checks for the config checks in internal/rules
// (threat T4). They delegate to the helpers that RedactURL and RedactArgs use,
// so the rules and the redaction agree on what looks like a secret. Neither
// function prints, logs or stores its input.

// HasTokenPrefix reports whether s starts with the prefix of a well-known API
// token format, such as "ghp_", "github_pat_", "sk-" or "xox", in any case,
// and has more text after the prefix. It does not look at the rest of s, so a
// match is a strong hint, not proof. It never prints or stores s.
//
// internal/rules uses it to find a plaintext secret in a config value
// (threat T4).
func HasTokenPrefix(s string) bool {
	return hasTokenPrefix(s)
}

// IsSecretName reports whether name looks like the name of a credential, such
// as an env variable or a header or flag name. name is split into words, so
// "api-key", "API_KEY" and "apiKey" all match through the word "key". Words
// such as "token", "secret", "password" and "auth" match anywhere in the name.
// Short forms such as "pass", "pin" and "jwt" match only as a whole word, or as
// the end of an all-caps word, so "bypass" and "path" do not match. It never
// prints or stores name.
//
// internal/rules uses it to decide whether an env or header key can hold a
// secret (threat T4).
func IsSecretName(name string) bool {
	return isSecretName(name)
}
