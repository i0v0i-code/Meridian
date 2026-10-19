package main

import (
	"fmt"
	"net"
	"strings"
	"time"

	proxyproto "github.com/pires/go-proxyproto"
)

// This allowlist is deliberately separate from TRUSTED_PROXY_CIDRS. A PROXY
// sender supplies transport identity; trusting HTTP headers is a different
// decision and must not automatically follow from enabling this listener.
func parsePanelProxyProtocolCIDRs(value string) ([]*net.IPNet, error) {
	if strings.TrimSpace(value) == "" {
		return nil, nil
	}
	var networks []*net.IPNet
	for _, entry := range strings.Split(value, ",") {
		_, network, err := net.ParseCIDR(strings.TrimSpace(entry))
		if err != nil {
			return nil, fmt.Errorf("invalid PANEL_PROXY_PROTOCOL_TRUSTED_CIDRS entry %q: %w", entry, err)
		}
		networks = append(networks, network)
	}
	return networks, nil
}

// Wrap before tls.NewListener: the PROXY header precedes the TLS ClientHello.
// Untrusted peers may use normal HTTP/TLS (including the loopback healthcheck),
// but cannot send a PROXY header. Trusted senders MUST send one, so a broken
// edge configuration fails closed instead of silently recording the proxy IP.
func wrapPanelProxyProtocol(listener net.Listener, trusted []*net.IPNet) net.Listener {
	if len(trusted) == 0 {
		return listener
	}
	return &proxyproto.Listener{
		Listener:          listener,
		ReadHeaderTimeout: 5 * time.Second,
		ConnPolicy: func(options proxyproto.ConnPolicyOptions) (proxyproto.Policy, error) {
			if options.Upstream != nil && isTrustedProxy(remoteAddressIP(options.Upstream.String()), trusted) {
				return proxyproto.REQUIRE, nil
			}
			return proxyproto.REJECT, nil
		},
	}
}
