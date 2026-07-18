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
	// SubscribeAckTimeout is how long to wait for the control plane to acknowledge
	// a new subscription with initial config. If the timeout is reached, the
	// attachment is detached. Set to 0 to disable (attach proceeds without waiting).
	SubscribeAckTimeout time.Duration `mapstructure:"subscribe_ack_timeout"`
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
	return nil
}

func (c *Config) DBPath() string {
	if c.DataDir == "" {
		return ":memory:"
	}
	return c.DataDir + "/netfence.db"
}
