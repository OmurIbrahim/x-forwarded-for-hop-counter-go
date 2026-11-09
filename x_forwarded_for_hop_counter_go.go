// Package xforwardedforhopcounter parses X-Forwarded-For headers and
// trims them to a trusted proxy hop count, returning the originating
// client IP.
//
// The X-Forwarded-For header is a comma-separated list of IP addresses,
// where each proxy appends the address it received the request from. The
// leftmost address is the original client, and the rightmost is the
// address of the last proxy before the server. When a server sits behind
// a known number of trusted proxies, the address at position
// len(parts) - trustedHops - 1 is the client address as seen by the
// outermost trusted proxy. Addresses to the right of that position are
// trusted proxies and are discarded.
//
// This implementation makes one deliberate simplification: it does not
// validate that the discarded addresses are well-formed IPs, because the
// caller has already decided to trust them by supplying a hop count. It
// does validate the returned client address, since that is the value the
// caller will act on.
package xforwardedforhopcounter

import (
	"errors"
	"net"
	"strings"
)

// ErrEmptyHeader is returned when the header is empty or contains no
// non-empty entries.
var ErrEmptyHeader = errors.New("x-forwarded-for header is empty")

// ErrTrustedHopsTooLarge is returned when trustedHops is greater than or
// equal to the number of entries in the header. In that case there is no
// position left for a client address: every entry is claimed to be a
// trusted proxy.
var ErrTrustedHopsTooLarge = errors.New("trusted hop count exceeds header entries")

// ErrInvalidClientIP is returned when the computed client address is not
// a valid IP address.
var ErrInvalidClientIP = errors.New("computed client address is not a valid IP")

// ClientIP parses the X-Forwarded-For header value and returns the
// originating client IP after removing trustedHops trusted proxy entries
// from the right-hand side.
//
// trustedHops must be non-negative. A trustedHops of 0 means the caller
// trusts no proxies and wants the rightmost entry, which is the address
// of the peer that connected to the server. A trustedHops of 1 means the
// rightmost entry is a trusted proxy and the client is the entry to its
// left, and so on.
//
// Whitespace around each comma-separated entry is trimmed. Empty entries
// are treated as errors rather than skipped, because silently dropping
// them would shift the hop count and could return the wrong address.
func ClientIP(header string, trustedHops int) (string, error) {
	if trustedHops < 0 {
		return "", ErrTrustedHopsTooLarge
	}

	parts := strings.Split(header, ",")
	if len(parts) == 0 {
		return "", ErrEmptyHeader
	}

	cleaned := make([]string, 0, len(parts))
	for _, p := range parts {
		trimmed := strings.TrimSpace(p)
		if trimmed == "" {
			return "", ErrEmptyHeader
		}
		cleaned = append(cleaned, trimmed)
	}

	if trustedHops >= len(cleaned) {
		return "", ErrTrustedHopsTooLarge
	}

	idx := len(cleaned) - trustedHops - 1
	client := cleaned[idx]

	if net.ParseIP(client) == nil {
		return "", ErrInvalidClientIP
	}

	return client, nil
}
