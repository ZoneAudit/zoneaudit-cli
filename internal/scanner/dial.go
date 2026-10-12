package scanner

import (
	"context"
	"fmt"
	"net"
	"time"
)

// publicDialer connects only to public addresses (see IsPublicIP). It
// resolves the host itself and dials a validated IP, so the address checked
// is the address connected to: a DNS answer that changes between lookups
// (DNS rebinding) cannot steer a connection to a loopback, private or
// link-local address such as a cloud metadata service. The caller keeps
// the original host name for TLS SNI and the HTTP Host header.
//
// resolver is the scanner's rate-limited resolver, so every lookup is
// counted in requests and waits for the shared limiter. The transports
// call Resolve before their own limiter wait and timeout start, so neither
// operation's wait eats into the other's timeout.
type publicDialer struct {
	resolver Resolver
	// timeout bounds a whole dial when ctx has no deadline: net/http dials
	// with a context detached from the request's deadline.
	timeout time.Duration
	// dial connects to a validated "ip:port"; tests replace it.
	dial func(ctx context.Context, network, address string) (net.Conn, error)
}

func newPublicDialer(resolver Resolver, timeout time.Duration) *publicDialer {
	d := &net.Dialer{Timeout: timeout}
	return &publicDialer{resolver: resolver, timeout: timeout, dial: d.DialContext}
}

// NonPublicAddressError is returned when a host has no public address to connect to.
type NonPublicAddressError struct {
	Host string
	IP   net.IP
}

func (e *NonPublicAddressError) Error() string {
	return fmt.Sprintf("not connecting to %s: %s is not a public address", e.Host, e.IP)
}

type resolvedKey struct{}

type resolvedHost struct {
	host string
	ips  []net.IP
}

// Resolve looks up host's public addresses and returns a context carrying
// them for DialContext. It fails, without any connection being attempted,
// when host has no public address.
func (d *publicDialer) Resolve(ctx context.Context, host string) (context.Context, error) {
	ips, err := d.publicAddrs(ctx, host)
	if err != nil {
		return ctx, err
	}
	return context.WithValue(ctx, resolvedKey{}, &resolvedHost{host: normaliseHost(host), ips: ips}), nil
}

// publicAddrs returns host's public addresses, in the resolver's order.
func (d *publicDialer) publicAddrs(ctx context.Context, host string) ([]net.IP, error) {
	var all []net.IP
	if ip := net.ParseIP(host); ip != nil {
		all = []net.IP{ip}
	} else {
		addrs, err := d.resolver.LookupHost(ctx, host)
		if err != nil {
			return nil, err
		}
		for _, a := range addrs {
			if ip := net.ParseIP(a); ip != nil {
				all = append(all, ip)
			}
		}
	}
	var public []net.IP
	var refused error
	for _, ip := range all {
		if IsPublicIP(ip) {
			public = append(public, ip)
		} else if refused == nil {
			refused = &NonPublicAddressError{Host: host, IP: ip}
		}
	}
	switch {
	case len(public) > 0:
		return public, nil
	case refused != nil:
		return nil, refused
	}
	return nil, &net.DNSError{Err: "no addresses", Name: host, IsNotFound: true}
}

// DialContext connects to a public address of address's host, using the
// addresses from Resolve when ctx carries them and looking them up
// otherwise.
func (d *publicDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	var ips []net.IP
	if r, ok := ctx.Value(resolvedKey{}).(*resolvedHost); ok && r.host == normaliseHost(host) {
		ips = r.ips
	} else if ips, err = d.publicAddrs(ctx, host); err != nil {
		return nil, err
	}
	if _, ok := ctx.Deadline(); !ok && d.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, d.timeout)
		defer cancel()
	}
	return d.dialAddrs(ctx, network, port, ips)
}

// fallbackDelay is how long the first address family is tried alone
// before the other family is raced against it, as with net.Dialer.
var fallbackDelay = 300 * time.Millisecond

// dialAddrs races the two address families ("Happy Eyeballs", RFC 8305):
// the family of the first address starts at once, the other after
// fallbackDelay or as soon as the first family fails. The first
// connection wins; any later one is closed.
func (d *publicDialer) dialAddrs(ctx context.Context, network, port string, ips []net.IP) (net.Conn, error) {
	var primary, fallback []net.IP
	firstIs4 := ips[0].To4() != nil
	for _, ip := range ips {
		if (ip.To4() != nil) == firstIs4 {
			primary = append(primary, ip)
		} else {
			fallback = append(fallback, ip)
		}
	}
	if len(fallback) == 0 {
		return d.dialSerial(ctx, network, port, primary)
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	type result struct {
		conn net.Conn
		err  error
	}
	results := make(chan result, 2)
	race := func(list []net.IP) {
		go func() {
			c, err := d.dialSerial(ctx, network, port, list)
			results <- result{c, err}
		}()
	}
	race(primary)
	started, pending := 1, 1
	timer := time.NewTimer(fallbackDelay)
	defer timer.Stop()
	var firstErr error
	for {
		select {
		case <-timer.C:
			if started == 1 {
				started, pending = 2, pending+1
				race(fallback)
			}
		case r := <-results:
			pending--
			if r.err == nil {
				if pending > 0 {
					go func(n int) {
						for ; n > 0; n-- {
							if late := <-results; late.conn != nil {
								late.conn.Close()
							}
						}
					}(pending)
				}
				return r.conn, nil
			}
			if firstErr == nil {
				firstErr = r.err
			}
			if started == 1 {
				started, pending = 2, pending+1
				race(fallback)
			} else if pending == 0 {
				return nil, firstErr
			}
		}
	}
}

// minDialTime is the least time each address gets when several share one
// deadline, as with net.Dialer.
const minDialTime = 2 * time.Second

// dialSerial tries ips in order. When ctx has a deadline, each address gets
// a share of the time left (at least minDialTime, if that much is left),
// so an address that never answers cannot use up the time of the next.
func (d *publicDialer) dialSerial(ctx context.Context, network, port string, ips []net.IP) (net.Conn, error) {
	var lastErr error
	for i, ip := range ips {
		if err := ctx.Err(); err != nil {
			if lastErr == nil {
				lastErr = err
			}
			break
		}
		dctx, cancel := ctx, context.CancelFunc(func() {})
		if dl, ok := ctx.Deadline(); ok {
			dctx, cancel = context.WithTimeout(ctx, partialTimeout(time.Until(dl), len(ips)-i))
		}
		c, err := d.dial(dctx, network, net.JoinHostPort(ip.String(), port))
		cancel()
		if err == nil {
			return c, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

// partialTimeout splits the time left between the addresses left to try.
func partialTimeout(left time.Duration, addrsLeft int) time.Duration {
	t := left / time.Duration(addrsLeft)
	if t < minDialTime {
		if left < minDialTime {
			return left
		}
		return minDialTime
	}
	return t
}
