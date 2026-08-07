package proxy

import (
	"context"
	"errors"
	"log"
	"net"
)

// DirectDialer connects without the tunnel, but resolves through it once the system resolver has failed. A direct dial can only ask the ISP's resolver, and where a name is deliberately broken upstream the lookup returns NXDOMAIN while the host itself is perfectly reachable. Retrying the lookup inside the tunnel gets the real answer and still connects from the local address, so the exit IP a rule was written for does not change.
type DirectDialer struct {
	// Tunnel resolves the retried lookup; nil disables the fallback entirely.
	Tunnel Dialer

	// Ready reports whether the tunnel can carry the lookup.
	Ready func() bool

	// DNS is the resolver to query through the tunnel, as host:port.
	DNS string

	net net.Dialer
}

// DialContext tries the system resolver first so the fast path keeps the OS cache and pays no extra round trip; only a lookup failure is retried through the tunnel.
func (d *DirectDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	c, err := d.net.DialContext(ctx, network, address)
	if err == nil || !isLookupFailure(err) || !d.canRetry() {
		return c, err
	}
	host, port, splitErr := net.SplitHostPort(address)
	if splitErr != nil {
		return nil, err
	}
	ips, lookupErr := d.resolver().LookupNetIP(ctx, "ip4", host)
	if lookupErr != nil || len(ips) == 0 {
		return nil, err
	}
	log.Printf("proxy: %s did not resolve locally, resolved through the tunnel to %s", host, ips[0])
	var firstErr error
	for _, ip := range ips {
		conn, dialErr := d.net.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
		if dialErr == nil {
			return conn, nil
		}
		if firstErr == nil {
			firstErr = dialErr
		}
	}
	return nil, firstErr
}

func (d *DirectDialer) canRetry() bool {
	return d.Tunnel != nil && d.DNS != "" && (d.Ready == nil || d.Ready())
}

func (d *DirectDialer) resolver() *net.Resolver {
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return d.Tunnel.DialContext(ctx, network, d.DNS)
		},
	}
}

// isLookupFailure separates a name that did not resolve from a host that answered and refused: only the former can be rescued by asking a different resolver.
func isLookupFailure(err error) bool {
	var dnsErr *net.DNSError
	return errors.As(err, &dnsErr)
}
