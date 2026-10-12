package scanner

import (
	"context"
	"net"
	"net/http"
	"net/url"
	"strings"
)

// maxRedirects is how many redirects a banner request follows.
const maxRedirects = 2

type scopeKey struct{}

// WithScope returns a context whose HTTP banner requests may only be
// redirected to domain or its subdomains. RunScan sets it to the scanned
// domain; without it, a redirect must stay on the host first requested.
func WithScope(ctx context.Context, domain string) context.Context {
	return context.WithValue(ctx, scopeKey{}, normaliseHost(domain))
}

func normaliseHost(h string) string {
	return strings.ToLower(strings.TrimSuffix(h, "."))
}

// scopedRedirectPolicy wraps next (or, if nil, the default cap of
// maxRedirects) so that a redirect is not followed when it leaves the scan
// scope, uses another scheme or port, or points at an IP address. The
// redirect response itself is returned instead, so its status is reported.
func (s *Scanner) scopedRedirectPolicy(next func(*http.Request, []*http.Request) error) func(*http.Request, []*http.Request) error {
	return func(req *http.Request, via []*http.Request) error {
		scope, _ := req.Context().Value(scopeKey{}).(string)
		if scope == "" && len(via) > 0 {
			scope = normaliseHost(via[0].URL.Hostname())
		}
		// The cap and the scope apply before any caller-supplied policy,
		// which can only refuse more.
		if len(via) > maxRedirects || !redirectAllowed(req.URL, scope) {
			return http.ErrUseLastResponse
		}
		if next != nil {
			return next(req, via)
		}
		return nil
	}
}

// redirectAllowed reports whether a redirect to u stays inside scope.
func redirectAllowed(u *url.URL, scope string) bool {
	if scope == "" {
		return false
	}
	// Only the scheme's standard port: 443 for https, 80 for http.
	switch p := u.Port(); u.Scheme {
	case "https":
		if p != "" && p != "443" {
			return false
		}
	case "http":
		if p != "" && p != "80" {
			return false
		}
	default:
		return false
	}
	host := normaliseHost(u.Hostname())
	// An IP literal is never inside a domain's scope. The addresses a host
	// name resolves to are checked when connecting (see publicDialer), so
	// a second DNS answer cannot differ from the one that was checked.
	return net.ParseIP(host) == nil && InScope(host, scope)
}

// InScope reports whether host is domain or one of its subdomains.
func InScope(host, domain string) bool {
	host, domain = normaliseHost(host), normaliseHost(domain)
	return domain != "" && (host == domain || strings.HasSuffix(host, "."+domain))
}

// specialPurpose lists the IANA special-purpose address blocks (RFC 6890
// and its updates) that are not globally reachable, or that embed or
// translate to another address (6to4, Teredo, NAT64 local use), so a host
// resolving into them is never connected to. Sources: the IANA IPv4 and
// IPv6 Special-Purpose Address Registries.
var specialPurpose = func() []*net.IPNet {
	var out []*net.IPNet
	for _, c := range []string{
		// IPv4
		"0.0.0.0/8",       // "this network"
		"10.0.0.0/8",      // private
		"100.64.0.0/10",   // shared address space (carrier-grade NAT)
		"127.0.0.0/8",     // loopback
		"169.254.0.0/16",  // link-local, including cloud metadata
		"172.16.0.0/12",   // private
		"192.0.0.0/24",    // IETF protocol assignments
		"192.0.2.0/24",    // documentation (TEST-NET-1)
		"192.31.196.0/24", // AS112-v4
		"192.52.193.0/24", // AMT
		"192.88.99.0/24",  // deprecated 6to4 relay anycast
		"192.168.0.0/16",  // private
		"192.175.48.0/24", // direct delegation AS112
		"198.18.0.0/15",   // benchmarking
		"198.51.100.0/24", // documentation (TEST-NET-2)
		"203.0.113.0/24",  // documentation (TEST-NET-3)
		"224.0.0.0/4",     // multicast
		"240.0.0.0/4",     // reserved, including 255.255.255.255
		// IPv6
		"::/96",          // unspecified, loopback and deprecated IPv4-compatible
		"::/128",         // unspecified
		"::1/128",        // loopback
		"64:ff9b:1::/48", // local-use IPv4/IPv6 translation
		"100::/64",       // discard-only
		"2001::/23",      // IETF protocol assignments, including Teredo and benchmarking
		"2001:db8::/32",  // documentation
		"2002::/16",      // 6to4
		"3fff::/20",      // documentation
		"5f00::/16",      // segment routing (SRv6) SIDs
		"fc00::/7",       // unique local
		"fe80::/10",      // link-local
		"ff00::/8",       // multicast
	} {
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			panic(err)
		}
		out = append(out, n)
	}
	return out
}()

// IsPublicIP reports whether ip is a globally reachable unicast address
// (an IPv4-mapped IPv6 address is checked as IPv4):
// not in any special-purpose block above (loopback, private, link-local and
// cloud metadata, carrier-grade NAT, documentation, benchmarking, reserved,
// multicast and so on).
func IsPublicIP(ip net.IP) bool {
	if ip4 := ip.To4(); ip4 != nil {
		ip = ip4
	}
	if !ip.IsGlobalUnicast() {
		return false
	}
	for _, n := range specialPurpose {
		if n.Contains(ip) {
			return false
		}
	}
	return true
}
