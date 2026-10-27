package discover

// This file is compiled only with the tests. It gives the external test
// package (discover_test) access to unexported code. A file named
// export_test.go in the package itself is the usual Go way to do this.

// QuotedSpan is quotedSpan, for checkArgSecretsConsistent: ArgSecrets can
// return the value of a quoted span with its escapes removed, which is not
// a substring of the arg.
var QuotedSpan = quotedSpan
