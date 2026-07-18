package config

import (
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/spf13/viper"
)

type Config struct {
	DNS          DNSConfig          `mapstructure:"dns"`
	Filter       FilterConfig       `mapstructure:"filter"`
	ControlPlane ControlPlaneConfig `mapstructure:"control_plane"`
	DataDir      string             `mapstructure:"data_dir"`
	LogLevel     string             `mapstructure:"log_level"`
	Socket       string             `mapstructure:"socket"`
	Metadata     map[string]string  `mapstructure:"metadata"`
	// TTLJanitorInterval is how often the daemon scans attachments for
	// expired TTL'd rules and removes them from the eBPF filters. It bounds
	// how long past its TTL an entry can linger. Zero (or unset) falls back
	// to the default of 1s — it does NOT disable the janitor.
	TTLJanitorInterval time.Duration `mapstructure:"ttl_janitor_interval"`
}

type DNSConfig struct {
	ListenAddr string `mapstructure:"listen_addr"`
	PortMin    int    `mapstructure:"port_min"`
	PortMax    int    `mapstructure:"port_max"`
	Upstream   string `mapstructure:"upstream"`
	// MinFilterTTL is the minimum lifetime a DNS-resolved IP stays in the
	// eBPF filter, regardless of a smaller DNS record TTL (the filter
	// deadline is max(record TTL, this floor)). Prevents tiny record TTLs
	// from churning the rule maps. Zero (or unset) falls back to the default
	// of 60s — it does NOT disable the floor.
	MinFilterTTL time.Duration `mapstructure:"min_filter_ttl"`
}

type FilterConfig struct {
	// MaxRuleEntries sets the capacity of each eBPF rule map
	// (allowed/denied, IPv4/IPv6) per attachment at filter load time.
	// Zero (or unset) keeps the compiled-in default of 4096. This is
	// load-time map sizing only; it has no per-packet cost.
	MaxRuleEntries int `mapstructure:"max_rule_entries"`
	// BPFPinDir is the bpffs directory the daemon pins each attachment's BPF
	// links and maps under (one subdirectory per attachment ID). Pinned state
	// is held by the kernel independent of the daemon process: enforcement
	// (and the rule set) survives daemon crashes, stops, and upgrades, and is
	// re-adopted on the next start. Default /sys/fs/bpf/netfence. An explicit
	// empty string disables pinning (BPF state dies with the process — every
	// daemon stop becomes fail-open).
	BPFPinDir string `mapstructure:"bpf_pin_dir"`
	// DetachOnStop controls what a daemon stop (SIGTERM/SIGINT) does with
	// attached filters. Default false: filters stay attached via their bpffs
	// pins and the kernel KEEPS ENFORCING the last-known policy while the
	// daemon is down (fail-closed; the next start re-adopts them). Set true
	// to detach filters and remove their pins on stop, leaving traffic
	// unfiltered while the daemon is down (fail-open).
	DetachOnStop bool `mapstructure:"detach_on_stop"`
}

type ControlPlaneConfig struct {
	URL string `mapstructure:"url"`
	// TLS configures transport security for the control-plane connection.
	// The presence of the block (even empty: `tls: {}`) enables TLS; an
	// empty/absent `ca` verifies the server against the system root pool.
	// When a URL is set, either this block or `insecure: true` MUST be
	// configured — there is no implicit-plaintext default (fail closed).
	TLS *ControlPlaneTLSConfig `mapstructure:"tls"`
	// Insecure explicitly opts into a plaintext (unencrypted,
	// unauthenticated) control-plane connection, e.g. for local
	// development. Mutually exclusive with the tls block.
	Insecure bool `mapstructure:"insecure"`
	// AuthToken, if set, is sent as `authorization: Bearer <token>`
	// metadata on every control-plane RPC. It is refused on a plaintext
	// channel unless `insecure: true` was explicitly set.
	AuthToken string `mapstructure:"auth_token"`
	// SubscribeAckTimeout is how long to wait for the control plane to acknowledge
	// a new subscription with initial config. If the timeout is reached, the
	// attachment is detached. Set to 0 to disable (attach proceeds without waiting).
	SubscribeAckTimeout time.Duration `mapstructure:"subscribe_ack_timeout"`
	// KeepaliveTime is how long the control-plane connection may be idle
	// before the daemon sends an HTTP/2 keepalive ping; KeepaliveTimeout is
	// how long it waits for the ping ack before declaring the peer dead and
	// reconnecting. Together they bound dead-peer detection to roughly
	// keepalive_time + keepalive_timeout instead of the kernel's
	// multi-minute TCP timeout. Zero (or unset) falls back to the defaults
	// of 30s / 10s — it does NOT disable keepalive. Note that gRPC clamps
	// the ping interval to a 10s client-side minimum, and the control plane
	// must permit this cadence in its keepalive enforcement policy.
	KeepaliveTime    time.Duration `mapstructure:"keepalive_time"`
	KeepaliveTimeout time.Duration `mapstructure:"keepalive_timeout"`
	// ReconnectBackoffMax caps the jittered exponential backoff between
	// control-plane reconnect attempts (starts at 1s, doubles, ±20%
	// jitter; resets to the floor only after a connection stayed healthy).
	// Zero (or unset) falls back to the default of 30s — it does NOT
	// disable the backoff.
	ReconnectBackoffMax time.Duration `mapstructure:"reconnect_backoff_max"`
}

// ControlPlaneTLSConfig configures TLS for the control-plane channel. Each
// certificate/key field accepts either a filesystem path or inline PEM
// (detected by a "-----BEGIN" marker).
type ControlPlaneTLSConfig struct {
	// CA is the certificate authority bundle used to verify the
	// control-plane server certificate. Empty uses the system root pool.
	CA string `mapstructure:"ca"`
	// Cert and Key are the daemon's client certificate and private key.
	// Setting both enables mTLS (the daemon presents the cert to the
	// server); setting only one is a config error.
	Cert string `mapstructure:"cert"`
	Key  string `mapstructure:"key"`
	// ServerName overrides the hostname used to verify the server
	// certificate (SNI), e.g. when dialing an IP address.
	ServerName string `mapstructure:"server_name"`
}

func Load(configPath string) (*Config, error) {
	v := viper.New()

	v.SetDefault("dns.listen_addr", "127.0.0.1")
	v.SetDefault("dns.port_min", 11000)
	v.SetDefault("dns.port_max", 11500)
	v.SetDefault("dns.upstream", "8.8.8.8:53")
	v.SetDefault("log_level", "info")
	v.SetDefault("socket", "/var/run/netfence.sock")
	v.SetDefault("dns.min_filter_ttl", 60*time.Second)
	v.SetDefault("filter.max_rule_entries", 4096)
	v.SetDefault("filter.bpf_pin_dir", "/sys/fs/bpf/netfence")
	v.SetDefault("filter.detach_on_stop", false)
	v.SetDefault("control_plane.subscribe_ack_timeout", 5*time.Second)
	v.SetDefault("control_plane.keepalive_time", 30*time.Second)
	v.SetDefault("control_plane.keepalive_timeout", 10*time.Second)
	v.SetDefault("control_plane.reconnect_backoff_max", 30*time.Second)
	v.SetDefault("ttl_janitor_interval", time.Second)

	v.SetEnvPrefix("NETFENCE")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	if configPath != "" {
		v.SetConfigFile(configPath)
		if err := v.ReadInConfig(); err != nil {
			return nil, fmt.Errorf("reading config file: %w", err)
		}
	}

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("unmarshaling config: %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("validating config: %w", err)
	}

	return &cfg, nil
}

func (c *Config) Validate() error {
	if c.DNS.PortMin > c.DNS.PortMax {
		return fmt.Errorf("dns.port_min (%d) must be <= dns.port_max (%d)", c.DNS.PortMin, c.DNS.PortMax)
	}
	if c.DNS.PortMin < 1 || c.DNS.PortMax > 65535 {
		return fmt.Errorf("dns port range must be within 1-65535")
	}
	if c.TTLJanitorInterval < 0 {
		return fmt.Errorf("ttl_janitor_interval must not be negative")
	}
	if c.DNS.MinFilterTTL < 0 {
		return fmt.Errorf("dns.min_filter_ttl must not be negative")
	}
	// 0 means "use the compiled-in default" (4096); anything else must fit
	// the kernel's u32 max_entries without truncation.
	if c.Filter.MaxRuleEntries < 0 || int64(c.Filter.MaxRuleEntries) > math.MaxUint32 {
		return fmt.Errorf("filter.max_rule_entries must be between 0 (default) and %d", uint32(math.MaxUint32))
	}
	return c.ControlPlane.validate()
}

// validate enforces the control-plane transport-security invariants. The
// key one is fail-closed: a configured URL with neither `tls` nor
// `insecure: true` is rejected instead of silently dialing plaintext (the
// pre-4A behavior). An empty URL (no control plane) is always valid.
func (c *ControlPlaneConfig) validate() error {
	if c.URL != "" {
		if c.TLS == nil && !c.Insecure {
			return fmt.Errorf("control_plane.url is set but transport security is not configured: set control_plane.tls (ca/cert/key/server_name; an empty block uses system roots) or explicitly opt into plaintext with control_plane.insecure: true")
		}
		if c.TLS != nil && c.Insecure {
			return fmt.Errorf("control_plane.tls and control_plane.insecure are mutually exclusive")
		}
	}
	if c.TLS != nil && (c.TLS.Cert == "") != (c.TLS.Key == "") {
		return fmt.Errorf("control_plane.tls.cert and control_plane.tls.key must be set together (both present enables mTLS)")
	}
	if c.KeepaliveTime < 0 {
		return fmt.Errorf("control_plane.keepalive_time must not be negative")
	}
	if c.KeepaliveTimeout < 0 {
		return fmt.Errorf("control_plane.keepalive_timeout must not be negative")
	}
	if c.ReconnectBackoffMax < 0 {
		return fmt.Errorf("control_plane.reconnect_backoff_max must not be negative")
	}
	return nil
}

func (c *Config) DBPath() string {
	if c.DataDir == "" {
		return ":memory:"
	}
	return c.DataDir + "/netfence.db"
}
