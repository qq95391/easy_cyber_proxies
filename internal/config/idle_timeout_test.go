package config

import (
	"testing"
	"time"
)

func TestIdleTimeoutDuration(t *testing.T) {
	cases := []struct {
		raw  string
		want time.Duration
	}{
		{"", 20 * time.Minute},
		{"20m", 20 * time.Minute},
		{"90s", 90 * time.Second},
		{"0", 0},
		{"0s", 0},
		{"-5m", 0},
		{"bogus", 0},
	}
	for _, tc := range cases {
		got := ListenerConfig{IdleTimeout: tc.raw}.IdleTimeoutDuration()
		if got != tc.want {
			t.Fatalf("IdleTimeoutDuration(%q) = %v, want %v", tc.raw, got, tc.want)
		}
	}
}
