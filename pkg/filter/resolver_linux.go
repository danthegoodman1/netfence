//go:build linux

package filter

import "fmt"

// Matches resolver_endpoint_config in filter_common.h (24 bytes).
type resolverEndpointConfig struct {
	Addr                           [16]byte
	PortMin, PortMax, Port, Family uint16
}

func (c *ruleMapCore) SetResolverEndpoint(endpoint ResolverEndpoint) error {
	if !endpoint.Address.IsValid() || endpoint.Address.Zone() != "" || endpoint.PortMin == 0 || endpoint.Port < endpoint.PortMin || endpoint.Port > endpoint.PortMax {
		return fmt.Errorf("invalid resolver endpoint")
	}
	want := resolverEndpointConfig{PortMin: endpoint.PortMin, PortMax: endpoint.PortMax, Port: endpoint.Port, Family: 6}
	if endpoint.Address.Is4() {
		addr := endpoint.Address.As4()
		copy(want.Addr[:4], addr[:])
		want.Family = 4
	} else {
		want.Addr = endpoint.Address.As16()
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.maps.resolver == nil {
		return fmt.Errorf("resolver isolation map is unavailable; controlled filter recreation is required")
	}
	var current resolverEndpointConfig
	if err := c.maps.resolver.Lookup(uint32(0), &current); err != nil {
		return err
	}
	if current == want {
		return nil
	}
	if current != (resolverEndpointConfig{}) {
		return fmt.Errorf("%w: resolver endpoint/range changed; retain pinned enforcement and recreate the attachment during a controlled upgrade", ErrPinnedSchemaIncompatible)
	}
	if err := c.maps.resolver.Put(uint32(0), want); err != nil {
		return err
	}
	if err := c.maps.resolver.Lookup(uint32(0), &current); err != nil {
		return err
	}
	if current != want {
		return fmt.Errorf("resolver isolation write could not be verified")
	}
	return nil
}
