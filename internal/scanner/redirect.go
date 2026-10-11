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
		if !redirectAllowed(req.URL, scope) {
			return http.ErrUseLastResponse
		}
		if next != nil {
			return next(req, via)
		}
		if len(via) > maxRedirects {
			return http.ErrUseLastResponse
		}
		return nil
	}
}

// redirectAllowed reports whether a redirect to u stays inside scope.
func redirectAllowed(u *url.URL, scope string) bool {
	if scope == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return false
	}
	if p := u.Port(); p != "" && p != "443" && p != "80" {
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

var sharedAddressSpace = &net.IPNet{IP: net.IPv4(100, 64, 0, 0), Mask: net.CIDRMask(10, 32)}

// IsPublicIP reports whether ip is a globally routable unicast address: not
// loopback, private, link-local (which includes cloud metadata addresses
// such as 169.254.169.254), multicast, unspecified or carrier-grade NAT.
func IsPublicIP(ip net.IP) bool {
	switch {
	case ip.IsLoopback(), ip.IsPrivate(), ip.IsLinkLocalUnicast(), ip.IsLinkLocalMulticast(),
		ip.IsInterfaceLocalMulticast(), ip.IsMulticast(), ip.IsUnspecified():
		return false
	}
	if ip4 := ip.To4(); ip4 != nil && (ip4[0] == 0 || sharedAddressSpace.Contains(ip4)) {
		return false
	}
	return ip.IsGlobalUnicast()
}
