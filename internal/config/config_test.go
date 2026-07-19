package config

import (
	"math"
	"strings"
	"testing"
)

func TestValidateIndependentDNSExactMapCapacity(t *testing.T) {
	cfg := validBase()
	cfg.Filter.MaxRuleEntries = 17
	cfg.Filter.MaxDNSRuleEntries = 3
	if err := cfg.Validate(); err != nil {
		t.Fatalf("independent capacities should validate: %v", err)
	}
	cfg.Filter.MaxDNSRuleEntries = -1
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "filter.max_dns_rule_entries") {
		t.Fatalf("negative DNS exact capacity should name its knob, got %v", err)
	}
	if int64(math.MaxUint32) < int64(^uint(0)>>1) {
		cfg.Filter.MaxDNSRuleEntries = int(math.MaxUint32) + 1
		if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "filter.max_dns_rule_entries") {
			t.Fatalf("overflowing DNS exact capacity should be rejected, got %v", err)
		}
	}
}

// validBase returns a Config that passes every non-control-plane Validate
// check, so control-plane cases only exercise the invariant under test.
func validBase() *Config {
	return &Config{
		DNS: DNSConfig{PortMin: 11000, PortMax: 11500},
	}
}

// TestValidate_ControlPlaneFailClosed is the 4A headline: a control-plane
// URL with neither `tls` nor an explicit `insecure: true` must be rejected
// at config time instead of silently dialing plaintext.
func TestValidate_ControlPlaneFailClosed(t *testing.T) {
	cfg := validBase()
	cfg.ControlPlane.URL = "cp.example.com:443"

	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected Validate to reject control_plane.url without tls or insecure, got nil")
	}
	for _, want := range []string{"control_plane.tls", "control_plane.insecure"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q should name %q so the fix is actionable", err, want)
		}
	}
}

func TestValidate_ControlPlaneSecurityCombinations(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*Config)
		wantErr string // empty = valid
	}{
		{
			name:   "empty URL, no security config",
			mutate: func(c *Config) {},
		},
		{
			name: "URL with tls block",
			mutate: func(c *Config) {
				c.ControlPlane.URL = "cp.example.com:443"
				c.ControlPlane.TLS = &ControlPlaneTLSConfig{CA: "/etc/netfence/ca.pem"}
			},
		},
		{
			name: "URL with empty tls block (system roots)",
			mutate: func(c *Config) {
				c.ControlPlane.URL = "cp.example.com:443"
				c.ControlPlane.TLS = &ControlPlaneTLSConfig{}
			},
		},
		{
			name: "URL with explicit insecure opt-in",
			mutate: func(c *Config) {
				c.ControlPlane.URL = "localhost:9000"
				c.ControlPlane.Insecure = true
			},
		},
		{
			name: "URL with tls and insecure is contradictory",
			mutate: func(c *Config) {
				c.ControlPlane.URL = "cp.example.com:443"
				c.ControlPlane.TLS = &ControlPlaneTLSConfig{}
				c.ControlPlane.Insecure = true
			},
			wantErr: "mutually exclusive",
		},
		{
			name: "client cert without key",
			mutate: func(c *Config) {
				c.ControlPlane.URL = "cp.example.com:443"
				c.ControlPlane.TLS = &ControlPlaneTLSConfig{Cert: "/etc/netfence/client.pem"}
			},
			wantErr: "must be set together",
		},
		{
			name: "client key without cert",
			mutate: func(c *Config) {
				c.ControlPlane.URL = "cp.example.com:443"
				c.ControlPlane.TLS = &ControlPlaneTLSConfig{Key: "/etc/netfence/client.key"}
			},
			wantErr: "must be set together",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validBase()
			tt.mutate(cfg)
			err := cfg.Validate()
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("expected valid config, got error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("expected error containing %q, got %q", tt.wantErr, err)
			}
		})
	}
}
