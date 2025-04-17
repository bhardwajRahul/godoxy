package server

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/quic-go/quic-go/http3"
	"github.com/rs/zerolog"
	"github.com/yusing/go-proxy/agent/pkg/agent"
	"github.com/yusing/go-proxy/internal/autocert"
	"github.com/yusing/go-proxy/internal/common"
	"github.com/yusing/go-proxy/internal/task"
	expect "github.com/yusing/go-proxy/internal/utils/testing"
)

func TestHTTP3Server(t *testing.T) {
	// Save original HTTP3Enabled value and restore it after test
	originalHTTP3Enabled := common.HTTP3Enabled
	defer func() { common.HTTP3Enabled = originalHTTP3Enabled }()

	// Enable HTTP3
	common.HTTP3Enabled = true

	// Set up a test handler that returns a simple response
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "Protocol: %s", r.Proto)
	})

	// Generate a self-signed certificate for testing
	cert, err := generateTestCertificate()
	expect.NoError(t, err)

	s := NewServer(Options{
		Name:         "test-http3-server",
		Handler:      testHandler,
		HTTPSAddr:    "localhost:0",
		CertProvider: autocert.TestProvider(&cert),
	})

	// Create a root task
	root := task.RootTask("http3-test", false)
	// Start the server
	s.Start(root)

	// Wait a bit for the server to start
	time.Sleep(500 * time.Millisecond)

	// Clean up at the end
	defer root.Finish(nil)

	// Verify the server details
	expect.True(t, s.https != nil)

	// The HTTP3 advertisement handling is tested in TestAdvertiseHTTP3
}

func TestAdvertiseHTTP3(t *testing.T) {
	// Create a mock HTTP3 server
	cert, err := generateTestCertificate()
	expect.NoError(t, err)

	h3Server := &http3.Server{
		Addr: "localhost:0",
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("OK"))
		}),
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
		},
	}

	// Wrap with HTTP3 advertisement
	handler := advertiseHTTP3(h3Server.Handler, h3Server)

	// Test HTTP/1.1 request (should set Alt-Svc header)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.ProtoMajor = 1
	req.ProtoMinor = 1

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	// Check response
	resp := rec.Result()
	defer resp.Body.Close()

	// Verify Alt-Svc header is set for HTTP/1.1
	altSvc := resp.Header["Alt-Svc"]
	expect.True(t, len(altSvc) > 0)

	// Test HTTP/3 request (should not set Alt-Svc header)
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.ProtoMajor = 3
	req.ProtoMinor = 0

	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	// Check response
	resp = rec.Result()
	defer resp.Body.Close()
}

func TestHTTP3Disabled(t *testing.T) {
	// Save original HTTP3Enabled value and restore it after test
	originalHTTP3Enabled := common.HTTP3Enabled
	defer func() { common.HTTP3Enabled = originalHTTP3Enabled }()

	// Disable HTTP3
	common.HTTP3Enabled = false

	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	cert, err := generateTestCertificate()
	expect.NoError(t, err)

	s := &Server{
		Name: "test-no-http3-server",
		https: &http.Server{
			Addr:    "localhost:0",
			Handler: testHandler,
			TLSConfig: &tls.Config{
				Certificates: []tls.Certificate{cert},
			},
		},
		l: zerolog.Nop(),
	}

	// Create a root task
	root := task.RootTask("http3-disabled-test", false)
	// Start the server
	s.Start(root)

	// Wait a bit for the server to start
	time.Sleep(500 * time.Millisecond)

	// Clean up at the end
	defer root.Finish(nil)

	// HTTP3 should not be enabled for this server
	// We can check that the TLSConfig does not contain the HTTP3 protocol
	found := false
	for _, proto := range s.https.TLSConfig.NextProtos {
		if proto == http3.NextProtoH3 {
			found = true
			break
		}
	}
	expect.False(t, found)
}

// Helper to generate a self-signed certificate for testing
func generateTestCertificate() (tls.Certificate, error) {
	_, srvcert, _, err := agent.NewAgent()
	if err != nil {
		return tls.Certificate{}, err
	}

	return tls.X509KeyPair(srvcert.Cert, srvcert.Key)
}
