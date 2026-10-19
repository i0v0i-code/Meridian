package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	proxyproto "github.com/pires/go-proxyproto"
)

func TestPanelProxyProtocolConfiguration(t *testing.T) {
	for _, value := range []string{"", "  ", "127.0.0.1/32", "192.0.2.0/24, 2001:db8::/32"} {
		if _, err := parsePanelProxyProtocolCIDRs(value); err != nil {
			t.Fatalf("valid configuration %q: %v", value, err)
		}
	}
	for _, value := range []string{"127.0.0.1", "0.0.0.0/33", ",", "127.0.0.1/32,"} {
		if _, err := parsePanelProxyProtocolCIDRs(value); err == nil {
			t.Fatalf("accepted malformed allowlist %q", value)
		}
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if got := wrapPanelProxyProtocol(l, nil); got != l {
		t.Fatal("disabled feature must leave listener unchanged")
	}
}

func TestPanelProxyProtocolTLSIdentity(t *testing.T) {
	for _, version := range []byte{1, 2} {
		for _, ip := range []string{"198.51.100.42", "2001:db8::42"} {
			t.Run(fmt.Sprintf("v%d/%s", version, ip), func(t *testing.T) {
				s := proxyProtocolTestServer(t, "127.0.0.1/32")
				client := proxyProtocolTestClient(t, s, version, ip)
				req, _ := http.NewRequest(http.MethodGet, s.URL, nil)
				// HTTP forwarding headers from the visitor must not override the
				// transport identity supplied by the trusted TCP proxy.
				req.Header.Set("X-Real-IP", "203.0.113.99")
				req.Header.Set("X-Forwarded-For", "203.0.113.99")
				resp, err := client.Do(req)
				if err != nil {
					t.Fatal(err)
				}
				defer resp.Body.Close()
				body, err := io.ReadAll(resp.Body)
				if err != nil {
					t.Fatal(err)
				}
				want := strings.Join([]string{ip, ip, ip, ip, "https"}, "|")
				if string(body) != want {
					t.Fatalf("identity = %q, want %q", body, want)
				}
			})
		}
	}
}

func TestPanelProxyProtocolTrustBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name, trusted string
		version       byte
		ok            bool
	}{
		{"required_header_missing", "127.0.0.1/32", 0, false},
		{"untrusted_v1_rejected", "192.0.2.0/24", 1, false},
		{"untrusted_v2_rejected", "192.0.2.0/24", 2, false},
		{"direct_healthcheck_allowed", "192.0.2.0/24", 0, true},
		{"disabled_direct_allowed", "", 0, true},
		{"disabled_header_rejected", "", 2, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := proxyProtocolTestServer(t, tc.trusted)
			client := proxyProtocolTestClient(t, s, tc.version, "198.51.100.42")
			resp, err := client.Get(s.URL)
			if resp != nil {
				resp.Body.Close()
			}
			if (err == nil) != tc.ok {
				t.Fatalf("success=%v, expected=%v; error=%v", err == nil, tc.ok, err)
			}
		})
	}
}

func TestPanelProxyProtocolHeaderTimeout(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	trusted, _ := parsePanelProxyProtocolCIDRs("127.0.0.1/32")
	w := wrapPanelProxyProtocol(l, trusted).(*proxyproto.Listener)
	w.ReadHeaderTimeout = 50 * time.Millisecond
	defer w.Close()
	client, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server, err := w.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	if _, err := client.Write([]byte("PROXY TCP4 ")); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := server.Read(make([]byte, 1)); done <- err }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("incomplete header accepted")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("incomplete header did not time out")
	}
}

func proxyProtocolTestServer(t *testing.T, cidrs string) *httptest.Server {
	t.Helper()
	s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil {
			t.Error("TLS state lost")
		}
		event := newRequestLogEvent(Site{}, r, nil)
		headers := make(http.Header)
		setTrustedForwardingHeaders(headers, r)
		fmt.Fprint(w, strings.Join([]string{requestClientKey(r, nil), event.ClientIP, headers.Get("X-Real-IP"), headers.Get("X-Forwarded-For"), headers.Get("X-Forwarded-Proto")}, "|"))
	}))
	trusted, err := parsePanelProxyProtocolCIDRs(cidrs)
	if err != nil {
		t.Fatal(err)
	}
	s.Listener = wrapPanelProxyProtocol(s.Listener, trusted)
	s.StartTLS()
	t.Cleanup(s.Close)
	return s
}

func proxyProtocolTestClient(t *testing.T, s *httptest.Server, version byte, ip string) *http.Client {
	t.Helper()
	transport := s.Client().Transport.(*http.Transport).Clone()
	transport.DialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		c, err := (&net.Dialer{}).DialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		if version != 0 {
			src := &net.TCPAddr{IP: net.ParseIP(ip), Port: 45678}
			dstIP := net.ParseIP("203.0.113.1")
			if src.IP.To4() == nil {
				dstIP = net.ParseIP("2001:db8::1")
			}
			header := proxyproto.HeaderProxyFromAddrs(version, src, &net.TCPAddr{IP: dstIP, Port: 443})
			if _, err := header.WriteTo(c); err != nil {
				c.Close()
				return nil, err
			}
		}
		config := transport.TLSClientConfig.Clone()
		config.ServerName, _, err = net.SplitHostPort(addr)
		if err != nil {
			c.Close()
			return nil, err
		}
		tlsConn := tls.Client(c, config)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			c.Close()
			return nil, err
		}
		return tlsConn, nil
	}
	t.Cleanup(transport.CloseIdleConnections)
	return &http.Client{Transport: transport, Timeout: 3 * time.Second}
}
