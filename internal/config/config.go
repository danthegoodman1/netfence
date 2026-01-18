package config

import (
	"fmt"
	"strings"

	"github.com/spf13/viper"
)

type Config struct {
	DNS          DNSConfig          `mapstructure:"dns"`
	ControlPlane ControlPlaneConfig `mapstructure:"control_plane"`
	DataDir      string             `mapstructure:"data_dir"`
	LogLevel     string             `mapstructure:"log_level"`
	Socket       string             `mapstructure:"socket"`
	Metadata     map[string]string  `mapstructure:"metadata"`
}

type DNSConfig struct {
	ListenAddr string `mapstructure:"listen_addr"`
	PortMin    int    `mapstructure:"port_min"`
	PortMax    int    `mapstructure:"port_max"`
	Upstream   string `mapstructure:"upstream"`
}

type ControlPlaneConfig struct {
	URL string `mapstructure:"url"`
}

func Load(configPath string) (*Config, error) {
	v := viper.New()

	v.SetDefault("dns.listen_addr", "127.0.0.1")
	v.SetDefault("dns.port_min", 11000)
	v.SetDefault("dns.port_max", 11500)
	v.SetDefault("dns.upstream", "8.8.8.8:53")
	v.SetDefault("log_level", "info")
	v.SetDefault("socket", "/var/run/netfence.sock")

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
	return nil
}

func (c *Config) DBPath() string {
	if c.DataDir == "" {
		return ":memory:"
	}
	return c.DataDir + "/netfence.db"
}
