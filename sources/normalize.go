package sources

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// This file is the single definition of asset identity normalization.
// Hostname casing, default ports and scheme prefixes are handled here and
// nowhere else; both the merger and any future consumer must go through
// NormalizeAsset / AssetKey so identities stay comparable.

// defaultSchemePorts maps a URL scheme to the port it implies when no
// explicit port is present.
var defaultSchemePorts = map[string]int{
	"http":   80,
	"https":  443,
	"ftp":    21,
	"ssh":    22,
	"telnet": 23,
	"smtp":   25,
	"pop3":   110,
	"imap":   143,
}

// DefaultPortForScheme returns the well-known port for a scheme, or 0 when
// the scheme has no default port known to uncover.
func DefaultPortForScheme(scheme string) int {
	return defaultSchemePorts[strings.ToLower(strings.TrimSpace(scheme))]
}

// NormalizeHost canonicalizes a host value as returned by the engines.
// Some engines return a bare hostname, some include a scheme prefix
// ("https://example.com"), some append a port ("example.com:8443") and some
// append a path. The returned value is the bare lowercased hostname without
// scheme, port, path or trailing dot. The returned port is the explicit port
// if one was present, else the default port of the scheme prefix if one was
// present, else 0.
func NormalizeHost(host string) (name string, port int) {
	h := strings.ToLower(strings.TrimSpace(host))
	if i := strings.Index(h, "://"); i >= 0 {
		port = DefaultPortForScheme(h[:i])
		h = h[i+3:]
	}
	if i := strings.IndexByte(h, '/'); i >= 0 {
		h = h[:i]
	}
	// strip userinfo if any slipped through (user@host)
	if i := strings.LastIndexByte(h, '@'); i >= 0 {
		h = h[i+1:]
	}
	if strings.HasPrefix(h, "[") {
		// bracketed IPv6, optionally with port: [::1]:443
		if end := strings.IndexByte(h, ']'); end >= 0 {
			name = h[1:end]
			rest := h[end+1:]
			if strings.HasPrefix(rest, ":") {
				if p, err := strconv.Atoi(rest[1:]); err == nil {
					port = p
				}
			}
			return name, port
		}
	}
	if i := strings.LastIndexByte(h, ':'); i >= 0 && !strings.Contains(h[i+1:], ":") {
		// single colon: host:port form (IPv6 without brackets reaches the
		// else branch since it contains more than one colon). Only a
		// numeric suffix overrides the scheme default.
		if p, err := strconv.Atoi(h[i+1:]); err == nil && p > 0 {
			port = p
			h = h[:i]
		}
	}
	name = strings.TrimSuffix(h, ".")
	return name, port
}

// NormalizeIP canonicalizes an IP literal (trim, lowercase so IPv6 forms
// compare equal).
func NormalizeIP(ip string) string {
	return strings.ToLower(strings.TrimSpace(ip))
}

// NormalizeAsset extracts the canonical identity of a result: normalized IP,
// normalized host and canonical port. The canonical port is the explicit
// result port, else a port embedded in the host value, else a port explicit
// in the URL, else the default port of the URL scheme, else 0 (unknown).
// The original result is never mutated; normalization only feeds identity.
func NormalizeAsset(r Result) (ip, host string, port int) {
	ip = NormalizeIP(r.IP)
	host, hostPort := NormalizeHost(r.Host)
	port = r.Port
	if port == 0 {
		port = hostPort
	}
	if r.Url != "" {
		if u, err := url.Parse(strings.TrimSpace(r.Url)); err == nil && u.Host != "" {
			if host == "" {
				host, _ = NormalizeHost(u.Host)
			}
			if port == 0 {
				if p := u.Port(); p != "" {
					if parsed, err := strconv.Atoi(p); err == nil {
						port = parsed
					}
				} else {
					port = DefaultPortForScheme(u.Scheme)
				}
			}
		}
	}
	// A port equal to the scheme default is canonical, not redundant: two
	// engines reporting https://host and https://host:443 both land on 443.
	return ip, host, port
}

// AssetKey returns the canonical identity key of a result. Results with an
// IP identify as ip:port, results without an IP identify as host:port. An
// empty key means the result carries no usable identity and is malformed for
// merging purposes.
func AssetKey(r Result) string {
	ip, host, port := NormalizeAsset(r)
	switch {
	case ip != "":
		return net.JoinHostPort(ip, fmt.Sprint(port))
	case host != "":
		return net.JoinHostPort(host, fmt.Sprint(port))
	default:
		return ""
	}
}
