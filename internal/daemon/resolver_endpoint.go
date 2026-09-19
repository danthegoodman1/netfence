package daemon

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"

	"github.com/danthegoodman1/netfence/pkg/filter"
)

func (s *Server) configureResolverEndpoint(f filter.Filter, address string) error {
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return err
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		return err
	}
	if host != s.dnsListenIP || port < s.cfg.DNS.PortMin || port > s.cfg.DNS.PortMax {
		return fmt.Errorf("persisted resolver %s differs from the configured listener/range; controlled attachment recreation is required", address)
	}
	guard, ok := f.(interface {
		SetResolverEndpoint(filter.ResolverEndpoint) error
	})
	if !ok {
		return fmt.Errorf("filter does not support resolver endpoint isolation")
	}
	return guard.SetResolverEndpoint(filter.ResolverEndpoint{Address: addr, Port: uint16(port), PortMin: uint16(s.cfg.DNS.PortMin), PortMax: uint16(s.cfg.DNS.PortMax)})
}
