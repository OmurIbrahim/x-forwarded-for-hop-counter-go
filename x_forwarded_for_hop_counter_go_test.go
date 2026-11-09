package xforwardedforhopcounter

import (
	"errors"
	"testing"
)

func TestClientIPHappyPaths(t *testing.T) {
	tests := []struct {
		name        string
		header      string
		trustedHops int
		want        string
	}{
		{
			name:        "single client no proxies",
			header:      "203.0.113.7",
			trustedHops: 0,
			want:        "203.0.113.7",
		},
		{
			name:        "client plus one trusted proxy",
			header:      "203.0.113.7, 198.51.100.4",
			trustedHops: 1,
			want:        "203.0.113.7",
		},
		{
			name:        "client plus two trusted proxies",
			header:      "203.0.113.7, 198.51.100.4, 192.0.2.9",
			trustedHops: 2,
			want:        "203.0.113.7",
		},
		{
			name:        "trust no proxies returns rightmost",
			header:      "203.0.113.7, 198.51.100.4, 192.0.2.9",
			trustedHops: 0,
			want:        "192.0.2.9",
		},
		{
			name:        "whitespace around entries is trimmed",
			header:      "  203.0.113.7 ,\t198.51.100.4\n",
			trustedHops: 1,
			want:        "203.0.113.7",
		},
		{
			name:        "IPv6 client",
			header:      "2001:db8::1, 192.0.2.9",
			trustedHops: 1,
			want:        "2001:db8::1",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ClientIP(tc.header, tc.trustedHops)
			if err != nil {
				t.Fatalf("ClientIP(%q, %d) returned unexpected error: %v", tc.header, tc.trustedHops, err)
			}
			if got != tc.want {
				t.Errorf("ClientIP(%q, %d) = %q, want %q", tc.header, tc.trustedHops, got, tc.want)
			}
		})
	}
}

func TestClientIPErrors(t *testing.T) {
	tests := []struct {
		name        string
		header      string
		trustedHops int
		wantErr     error
	}{
		{
			name:        "empty header",
			header:      "",
			trustedHops: 0,
			wantErr:     ErrEmptyHeader,
		},
		{
			name:        "only whitespace",
			header:      "   ",
			trustedHops: 0,
			wantErr:     ErrEmptyHeader,
		},
		{
			name:        "empty entry between commas",
			header:      "203.0.113.7,,198.51.100.4",
			trustedHops: 1,
			wantErr:     ErrEmptyHeader,
		},
		{
			name:        "trailing comma",
			header:      "203.0.113.7,",
			trustedHops: 0,
			wantErr:     ErrEmptyHeader,
		},
		{
			name:        "trusted hops equal entries",
			header:      "203.0.113.7, 198.51.100.4",
			trustedHops: 2,
			wantErr:     ErrTrustedHopsTooLarge,
		},
		{
			name:        "trusted hops exceed entries",
			header:      "203.0.113.7",
			trustedHops: 5,
			wantErr:     ErrTrustedHopsTooLarge,
		},
		{
			name:        "negative trusted hops",
			header:      "203.0.113.7",
			trustedHops: -1,
			wantErr:     ErrTrustedHopsTooLarge,
		},
		{
			name:        "client is not a valid IP",
			header:      "not-an-ip, 198.51.100.4",
			trustedHops: 1,
			wantErr:     ErrInvalidClientIP,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ClientIP(tc.header, tc.trustedHops)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("ClientIP(%q, %d) error = %v, want %v", tc.header, tc.trustedHops, err, tc.wantErr)
			}
			if got != "" {
				t.Errorf("ClientIP(%q, %d) = %q, want empty string on error", tc.header, tc.trustedHops, got)
			}
		})
	}
}
