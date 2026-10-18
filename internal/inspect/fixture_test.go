package inspect

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// This file holds shared helpers for the tests of the remote (HTTP)
// transports. It has no Test functions on purpose.

// fixtureInstructions is the instructions text of the fixture server.
const fixtureInstructions = "fixture instructions"

// echoInput is the input of the fixture "echo" tool.
type echoInput struct {
	Text string `json:"text"`
}

// addInput is the input of the fixture "add" tool.
type addInput struct {
	A int `json:"a"`
	B int `json:"b"`
}

// newFixtureMCPServer returns an MCP server with two tools ("echo" and
// "add"), one prompt ("greet") and one resource ("readme"). The server is
// benign. Tests use it as the remote end of an inspection.
func newFixtureMCPServer() *mcp.Server {
	srv := mcp.NewServer(
		&mcp.Implementation{Name: "fixture", Version: "1.2.3"},
		&mcp.ServerOptions{Instructions: fixtureInstructions},
	)

	mcp.AddTool(srv,
		&mcp.Tool{Name: "echo", Description: "Echo the input"},
		func(context.Context, *mcp.CallToolRequest, echoInput) (*mcp.CallToolResult, any, error) {
			return nil, nil, nil
		})
	mcp.AddTool(srv,
		&mcp.Tool{Name: "add", Description: "Add two numbers"},
		func(context.Context, *mcp.CallToolRequest, addInput) (*mcp.CallToolResult, any, error) {
			return nil, nil, nil
		})

	srv.AddPrompt(&mcp.Prompt{
		Name:        "greet",
		Description: "Say hello",
		Arguments:   []*mcp.PromptArgument{{Name: "name", Required: true}},
	}, func(context.Context, *mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
		return &mcp.GetPromptResult{}, nil
	})

	srv.AddResource(&mcp.Resource{
		URI:      "file:///fixture/readme.txt",
		Name:     "readme",
		MIMEType: "text/plain",
	}, func(context.Context, *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
		return &mcp.ReadResourceResult{}, nil
	})

	return srv
}

// fixtureWant returns the Result that an inspection of the fixture server
// must produce.
//
// ProtocolVersion is empty: client and server negotiate it, so tests only
// check that it is not empty. InputSchema and OutputSchema are nil for the
// same kind of reason: the SDK generates the schema JSON, and tests compare
// the schemas with schemaProps instead of byte for byte. Tests must copy the
// Result and clear these fields before they compare it with this value.
func fixtureWant() Result {
	return Result{
		ServerName:    "fixture",
		ServerVersion: "1.2.3",
		Instructions:  fixtureInstructions,
		// The SDK server lists tools sorted by name.
		Tools: []Tool{
			{Name: "add", Description: "Add two numbers"},
			{Name: "echo", Description: "Echo the input"},
		},
		Prompts: []Prompt{{
			Name:        "greet",
			Description: "Say hello",
			Arguments:   []PromptArgument{{Name: "name", Required: true}},
		}},
		Resources: []Resource{{
			URI:      "file:///fixture/readme.txt",
			Name:     "readme",
			MIMEType: "text/plain",
		}},
	}
}

// schemaProps returns the sorted property names of a JSON Schema object. It
// returns nil when the schema has no properties.
func schemaProps(t *testing.T, raw json.RawMessage) []string {
	t.Helper()
	var schema struct {
		Properties map[string]json.RawMessage `json:"properties"`
	}
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatalf("schemaProps: decode schema %q: %v", raw, err)
	}
	var names []string
	for name := range schema.Properties {
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}

// recordedRequest is one HTTP request that a recorder saw.
type recordedRequest struct {
	Method string
	Path   string
	Header http.Header
	// Body is the request body. It is empty for a request without one.
	Body []byte
}

// recorder records the HTTP requests that reach a server. It is safe for
// concurrent use.
type recorder struct {
	mu   sync.Mutex
	reqs []recordedRequest
}

// record returns a handler that records each request and then calls next.
// It reads the request body and puts it back, so next can read it too. Only
// a POST carries a body; the body of an SSE GET stream is never read.
func (r *recorder) record(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		var body []byte
		if req.Method == http.MethodPost && req.Body != nil {
			var err error
			body, err = io.ReadAll(req.Body)
			if err != nil {
				http.Error(w, "read body", http.StatusBadRequest)
				return
			}
			req.Body = io.NopCloser(bytes.NewReader(body))
		}
		r.mu.Lock()
		r.reqs = append(r.reqs, recordedRequest{
			Method: req.Method,
			Path:   req.URL.Path,
			Header: req.Header.Clone(),
			Body:   body,
		})
		r.mu.Unlock()
		next.ServeHTTP(w, req)
	})
}

// requests returns a copy of the recorded requests, oldest first.
func (r *recorder) requests() []recordedRequest {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.reqs)
}

// fixtureOpts configures startFixture.
type fixtureOpts struct {
	// TLS starts an HTTPS server with the httptest certificate.
	TLS bool
	// SSE serves the legacy SSE transport instead of Streamable HTTP.
	SSE bool
	// Stateless makes the Streamable HTTP handler stateless. A stateful
	// handler refuses protocol 2026-07-28, so the SDK client falls back to
	// an older version. A stateless handler accepts it, so set Stateless to
	// test the newest protocol. It has no effect with SSE.
	Stateless bool
	// Server, when set, is the MCP server to serve instead of the one from
	// newFixtureMCPServer. Use it to add middleware, for example.
	Server *mcp.Server
	// Wrap, when set, wraps the handler after the recorder. Use it to
	// reject requests, for example.
	Wrap func(http.Handler) http.Handler
	// ConnState, when set, is the http.Server ConnState hook. Use it to see
	// when the client opens and closes connections.
	ConnState func(net.Conn, http.ConnState)
}

// startFixture starts a server with the fixture MCP server at the path
// "/mcp" and returns it with a recorder of its requests. The server closes
// when the test ends. Use fixtureURL for the endpoint.
func startFixture(t *testing.T, opts fixtureOpts) (*httptest.Server, *recorder) {
	t.Helper()
	srv := opts.Server
	if srv == nil {
		srv = newFixtureMCPServer()
	}
	getServer := func(*http.Request) *mcp.Server { return srv }

	var h http.Handler
	if opts.SSE {
		h = mcp.NewSSEHandler(getServer, nil)
	} else {
		h = mcp.NewStreamableHTTPHandler(getServer, &mcp.StreamableHTTPOptions{Stateless: opts.Stateless})
	}

	mux := http.NewServeMux()
	mux.Handle("/mcp", h)

	rec := &recorder{}
	root := rec.record(mux)
	if opts.Wrap != nil {
		root = opts.Wrap(root)
	}

	ts := httptest.NewUnstartedServer(root)
	ts.Config.ConnState = opts.ConnState
	if opts.TLS {
		ts.StartTLS()
	} else {
		ts.Start()
	}
	t.Cleanup(ts.Close)
	return ts, rec
}

// fixtureURL returns the MCP endpoint URL of a server from startFixture.
func fixtureURL(ts *httptest.Server) string {
	return ts.URL + "/mcp"
}

// startTLSWithCert starts an HTTPS server for h that presents cert. The
// server closes when the test ends.
func startTLSWithCert(t *testing.T, h http.Handler, cert tls.Certificate) *httptest.Server {
	t.Helper()
	ts := httptest.NewUnstartedServer(h)
	ts.TLS = &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}
	ts.StartTLS()
	t.Cleanup(ts.Close)
	return ts
}

// genCert creates a self-signed ECDSA P-256 certificate that is valid from
// notBefore to notAfter for the given hosts. Each host is an IP address or a
// DNS name. The certificate is its own CA, so the returned pool, which holds
// it, lets a client trust it.
func genCert(t *testing.T, notBefore, notAfter time.Time, hosts ...string) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("genCert: generate key: %v", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	if err != nil {
		t.Fatalf("genCert: serial number: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "mcpmoat test"},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	for _, host := range hosts {
		if ip := net.ParseIP(host); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, host)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("genCert: create certificate: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("genCert: parse certificate: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	cert := tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  key,
		Leaf:        leaf,
	}
	return cert, pool
}

// clientTransport returns an HTTP transport that trusts only the CAs in
// pool. It never skips certificate verification.
func clientTransport(pool *x509.CertPool) http.RoundTripper {
	return &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs:    pool,
			MinVersion: tls.VersionTLS12,
		},
	}
}
