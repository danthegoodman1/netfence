package daemon

import "github.com/danthegoodman1/netfence/internal/config"

// Slots bound active work, including idle accepted TCP connections. Acquisition
// never queues: an overloaded UDP query is dropped and a TCP connection closed.
type dnsResources struct {
	queries     chan struct{}
	connections chan struct{}
}

func defaultPositive(value, fallback int) int {
	if value <= 0 {
		return fallback
	}
	return value
}

func newGlobalDNSResources(cfg config.DNSConfig) *dnsResources {
	return &dnsResources{
		queries:     make(chan struct{}, defaultPositive(cfg.MaxGlobalQueries, 4096)),
		connections: make(chan struct{}, defaultPositive(cfg.MaxGlobalTCPConnections, 1024)),
	}
}

func acquireDNSSlots(local, global chan struct{}) bool {
	select {
	case local <- struct{}{}:
	default:
		return false
	}
	if global != nil {
		select {
		case global <- struct{}{}:
		default:
			<-local
			return false
		}
	}
	return true
}

func releaseDNSSlots(local, global chan struct{}) {
	if global != nil {
		<-global
	}
	<-local
}
