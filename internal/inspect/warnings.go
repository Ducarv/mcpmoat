package inspect

import (
	"net/http"
	"net/netip"
	"net/url"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Ducarv/mcpmoat/internal/discover"
)

// The fixed list names that a WarnUndeclaredCapability warning holds in
// Warning.Capabilities. They are stable: reports and JSON output can show them.
const (
	capTools             = "tools"
	capPrompts           = "prompts"
	capResources         = "resources"
	capResourceTemplates = "resource-templates"
)

// cleartextWarnings returns a warning when Remote sends secrets to srv over
// plain http:// to a host that is not loopback (issue #98). u is the parsed
// server URL from parseEndpoint.
//
// Plain HTTP has no encryption. Anyone on the network path, for example on a
// shared Wi-Fi, and any proxy from HTTP_PROXY can read the requests, and so
// the header values, the Basic credentials from the URL user info and the
// secrets in the URL query and path. They can then use these credentials
// against the real server. Traffic to a loopback address does not leave the
// machine, so it gets no warning.
//
// This is a warning only. Remote still connects: a local or test server can
// use plain HTTP on purpose, and the user decides.
//
// It returns nil when the scheme is not http, when the host is loopback, or
// when no config header, no URL user info and no URL secret went out.
// Otherwise it returns one Warning of kind WarnCleartextSecrets with the
// header keys and the user info flag from sentHeaders, and the URL secrets
// flag from hasURLSecrets. It keeps no header value, no password and no part
// of the URL.
func cleartextWarnings(srv discover.Server, u *url.URL) []Warning {
	// url.Parse already lowercases the scheme. EqualFold keeps this check
	// correct even for a URL that was built another way.
	if u == nil || !strings.EqualFold(u.Scheme, "http") {
		return nil
	}
	if discover.IsLoopbackHost(u.Hostname()) {
		return nil
	}
	names, basic := sentHeaders(srv)
	// u comes from parseEndpoint(srv.URL.Reveal()) in Remote, so its query
	// and the path of the raw URL are the parts that Remote sends.
	inURL := hasURLSecrets(u.RawQuery, srv.URL.Reveal())
	if len(names) == 0 && !basic && !inURL {
		return nil
	}
	return []Warning{{
		Kind:        WarnCleartextSecrets,
		HeaderKeys:  names,
		URLUserInfo: basic,
		URLSecrets:  inURL,
	}}
}

// hasURLSecrets reports whether rawQuery or the path of raw, the configured
// URL, holds a part that discover.RedactURL masks (discover.SecretQueryParts
// and discover.SecretPathSegments). It returns a bool only, so no part of the
// URL can leak into a Warning.
//
// It does not use urlSecrets, which drops the parts shorter than
// discover.MinSecretBytes. That length limit keeps classify from removing
// short, common words from error text. For the warning, a short password in the
// query still goes out in clear text, so every part counts. RedactURL masks
// every query value, so a query such as "?page=1" gets the warning too. This
// errs on the safe side: mcpmoat cannot tell a harmless value from a short
// secret.
func hasURLSecrets(rawQuery, raw string) bool {
	return len(discover.SecretQueryParts(rawQuery)) > 0 ||
		len(discover.SecretPathSegments(raw)) > 0
}

// undeclaredWarnings returns a warning when the server answered a list that
// its capabilities caps do not declare, with at least one item (issue #97). r
// holds the lists that listInto read.
//
// A server that leaves a capability out of its declaration but still answers
// the list request can hide the list from a client that checks caps, and show
// it to a client that does not. It can also pick the clients that see the
// list. So items in an undeclared list are worth a look, even though mcpmoat
// reports them like any other item.
//
// A list counts as undeclared when caps is nil or its capability field is nil.
// Resource templates fall under the resources capability. A list that the
// server answered empty, or refused, gets no warning: some servers, the SDK
// server for example, answer every list request with an empty list.
//
// It returns nil when no undeclared list has items. Otherwise it returns one
// Warning of kind WarnUndeclaredCapability whose Capabilities hold the fixed
// names of those lists, in the order tools, prompts, resources,
// resource-templates. The Warning holds no server text.
func undeclaredWarnings(caps *mcp.ServerCapabilities, r Result) []Warning {
	var declTools, declPrompts, declResources bool
	if caps != nil {
		declTools = caps.Tools != nil
		declPrompts = caps.Prompts != nil
		declResources = caps.Resources != nil
	}

	var names []string
	if !declTools && len(r.Tools) > 0 {
		names = append(names, capTools)
	}
	if !declPrompts && len(r.Prompts) > 0 {
		names = append(names, capPrompts)
	}
	if !declResources && len(r.Resources) > 0 {
		names = append(names, capResources)
	}
	if !declResources && len(r.ResourceTemplates) > 0 {
		names = append(names, capResourceTemplates)
	}
	if len(names) == 0 {
		return nil
	}
	return []Warning{{
		Kind:         WarnUndeclaredCapability,
		Capabilities: names,
	}}
}

// dnsPinWarning returns a warning when a proxy keeps mcpmoat from pinning the
// DNS answer for the host of endpoint (issue #106). endpoint is the parsed
// server URL from parseEndpoint. proxy is the proxy function of the HTTP
// transport, for example proxyFromEnvironment.
//
// The pinned dialer resolves the server host one time and checks the
// addresses that it dials. When the request goes through a proxy, mcpmoat
// dials the proxy, and the proxy resolves the server host. The proxy can get a
// different answer, and the address checks do not apply to it. An IP literal
// host needs no DNS answer, so it gets no warning.
//
// This is a warning only. Remote still connects: the user chose the proxy.
//
// It returns nil when endpoint or proxy is nil, when the host is empty or an
// IP address, when proxy returns no proxy for the request, or when proxy
// returns an error. A proxy error is ignored here: the transport calls proxy
// again and reports the error itself. Otherwise it returns one Warning of kind
// WarnDNSPinUnavailable. The Warning holds no URL, neither the proxy URL nor
// the server URL, because the proxy URL can hold a user name and a password.
func dnsPinWarning(endpoint *url.URL, proxy func(*http.Request) (*url.URL, error)) []Warning {
	if endpoint == nil || proxy == nil {
		return nil
	}
	host := endpoint.Hostname()
	if host == "" {
		return nil
	}
	// netip.ParseAddr also accepts an IPv6 zone, such as "fe80::1%en0".
	if _, err := netip.ParseAddr(host); err == nil {
		return nil
	}
	// The proxy function reads only the request URL. Give it a copy, so that
	// it cannot change endpoint.
	u := *endpoint
	req := &http.Request{Method: http.MethodPost, URL: &u, Header: http.Header{}}
	p, err := proxy(req)
	if err != nil || p == nil {
		return nil
	}
	return []Warning{{Kind: WarnDNSPinUnavailable}}
}
