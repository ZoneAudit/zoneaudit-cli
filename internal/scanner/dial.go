package scanner

import (
	"context"
	"fmt"
	"net"
	"time"
)

// publicDialer connects only to public addresses. It resolves the host
// itself and dials a validated IP, so the address checked is the address
// connected to: a DNS answer that changes between lookups (DNS rebinding)
// cannot steer a connection to a loopback, private or link-local address
// such as a cloud metadata service. The caller keeps the original host
// name for TLS SNI and the HTTP Host header.
//
// Name resolution here is part of the request being made (as it was with
// the standard dialer), so it is not rate limited or counted separately.
type publicDialer struct {
	resolver Resolver
	// dial connects to a validated "ip:port"; tests replace it.
	dial func(ctx context.Context, network, address string) (net.Conn, error)
}

func newPublicDialer(resolver Resolver, timeout time.Duration) *publicDialer {
	d := &net.Dialer{Timeout: timeout}
	return &publicDialer{resolver: resolver, dial: d.DialContext}
}

// NonPublicAddressError is returned when a host has no public address to connect to.
type NonPublicAddressError struct {
	Host string
	IP   net.IP
}

func (e *NonPublicAddressError) Error() string {
	return fmt.Sprintf("not connecting to %s: %s is not a public address", e.Host, e.IP)
}

// DialContext resolves address's host, skips every address that is not
// public, and connects to the first public one that answers.
func (d *publicDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	var ips []net.IP
	if ip := net.ParseIP(host); ip != nil {
		ips = []net.IP{ip}
	} else {
		addrs, err := d.resolver.LookupHost(ctx, host)
		if err != nil {
			return nil, err
		}
		for _, a := range addrs {
			if ip := net.ParseIP(a); ip != nil {
				ips = append(ips, ip)
			}
		}
	}
	if len(ips) == 0 {
		return nil, &net.DNSError{Err: "no addresses", Name: host, IsNotFound: true}
	}
	var lastErr error
	for _, ip := range ips {
		if !IsPublicIP(ip) {
			lastErr = &NonPublicAddressError{Host: host, IP: ip}
			continue
		}
		conn, err := d.dial(ctx, network, net.JoinHostPort(ip.String(), port))
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}
	return nil, lastErr
}
