package querylang

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

// parseValueToken classifies and parses a bare (unquoted) value token into a
// typed leaf value. Quoted tokens always become KindString.
func parseValueToken(t token) (any, ValueKind, error) {
	if t.kind == tkString {
		return t.text, KindString, nil
	}
	text := t.text

	// IP address?
	if _, err := netip.ParseAddr(text); err == nil {
		return net.ParseIP(text), KindIP, nil
	}
	// CIDR?
	if _, ipNet, err := net.ParseCIDR(text); err == nil {
		return ipNet, KindCIDR, nil
	}
	// Port/IP range: 80-443 or 10.0.0.1-10.0.0.50
	if strings.Contains(text, "-") {
		return parseRangeToken(t)
	}
	// Plain number?
	if i, err := strconv.ParseInt(text, 10, 64); err == nil {
		return i, KindNumber, nil
	}
	if f, err := strconv.ParseFloat(text, 64); err == nil {
		return f, KindNumber, nil
	}
	// Bare word: treat as string (e.g. protocol value tcp, service http).
	return text, KindString, nil
}

func parseRangeToken(t token) (any, ValueKind, error) {
	parts := strings.SplitN(t.text, "-", 2)
	left, right := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
	if left == "" || right == "" {
		return nil, 0, newParseError("", t.pos, "range %q needs a value on both sides of '-'", t.text)
	}

	// Port range: both sides numeric.
	if lo, err := strconv.Atoi(left); err == nil {
		hi, err := strconv.Atoi(right)
		if err != nil {
			return nil, 0, newParseError("", t.pos, "range %q mixes numeric and non-numeric bounds", t.text)
		}
		if lo < 1 || hi > 65535 || lo > hi {
			return nil, 0, newParseError("", t.pos, "invalid port range %q: need 1 <= low <= high <= 65535", t.text)
		}
		return &PortRangeValue{Low: lo, High: hi}, KindPortRange, nil
	}

	// Otherwise both bounds must be IP addresses.
	start, err1 := netip.ParseAddr(left)
	end, err2 := netip.ParseAddr(right)
	if err1 != nil || err2 != nil {
		return nil, 0, newParseError("", t.pos, "range %q is neither a port range (80-443) nor an IP range (10.0.0.1-10.0.0.9)", t.text)
	}
	if start.BitLen() != end.BitLen() || start.Compare(end) > 0 {
		return nil, 0, newParseError("", t.pos, "invalid IP range %q: bounds must be the same address family and start <= end", t.text)
	}
	return &IPRangeValue{Start: start.String(), End: end.String()}, KindIPRange, nil
}

// parseTimeValue parses a quoted or bare timestamp into RFC3339 UTC text. It
// accepts RFC3339 with/without timezone and the compact yyyy-mm-dd form; the
// compact form is interpreted as UTC midnight so the meaning is unambiguous
// across builds.
func parseTimeValue(raw string) (string, error) {
	candidates := []string{
		time.RFC3339,
		"2006-01-02T15:04:05",
		"2006-01-02 15:04:05",
		"2006-01-02",
	}
	for _, layout := range candidates {
		if ts, err := time.Parse(layout, raw); err == nil {
			return ts.UTC().Format(time.RFC3339), nil
		}
	}
	return "", fmt.Errorf("invalid timestamp %q: expected RFC3339 (e.g. 2024-01-02T15:04:05Z) or yyyy-mm-dd", raw)
}

// parseTimeRange builds a TimeRangeValue from two raw timestamp tokens.
func parseTimeRange(fromRaw, toRaw string, pos int) (*TimeRangeValue, error) {
	from, err := parseTimeValue(fromRaw)
	if err != nil {
		return nil, newParseError("", pos, "%v", err)
	}
	to, err := parseTimeValue(toRaw)
	if err != nil {
		return nil, newParseError("", pos, "%v", err)
	}
	if from > to {
		return nil, newParseError("", pos, "time range %q..%q is reversed: from must be before to", fromRaw, toRaw)
	}
	return &TimeRangeValue{From: from, To: to}, nil
}
