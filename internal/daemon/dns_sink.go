package daemon

import (
	"fmt"
	"net"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog"

	"github.com/danthegoodman1/netfence/pkg/filter"
)

// DNSFilterSink receives DNS-resolved IPs destined for the packet filter.
// Implementations bound the entry's lifetime: the IP is allowed for at least
// ttl (subject to a configured floor) and reclaimed by the TTL janitor
// afterwards unless something longer-lived (e.g. a permanent control-plane
// rule for the same CIDR) pins it.
type DNSFilterSink interface {
	AllowIPWithTTL(cidr *net.IPNet, ttl time.Duration) error
}

// mapFullWarnInterval rate-limits the map-full warning per attachment so a
// stream of DNS resolutions against a full map does not flood the log. The
// cumulative drop count is carried in the message and in AttachmentStats.
const mapFullWarnInterval = 30 * time.Second

// dnsFilterSink is the Server's per-attachment DNSFilterSink: it routes
// DNS-resolved IPs through the attachment's TTL registry (so the janitor
// expires them) with the configured minimum filter TTL applied.
type dnsFilterSink struct {
	server *Server
	id     string
	filter filter.Filter
	reg    *ttlRegistry
	logger zerolog.Logger

	// lastMapFullWarn is the unixnano of the last map-full warning.
	lastMapFullWarn atomic.Int64
}

func (s *Server) newDNSFilterSink(id string, f filter.Filter, reg *ttlRegistry) *dnsFilterSink {
	return &dnsFilterSink{
		server: s,
		id:     id,
		filter: f,
		reg:    reg,
		logger: s.logger.With().Str("id", id).Logger(),
	}
}

func (s *dnsFilterSink) AllowIPWithTTL(cidr *net.IPNet, ttl time.Duration) error {
	state, done, err := s.server.beginAttachmentMutation(s.id)
	if err != nil {
		return err
	}
	defer done()
	// A sink is lifecycle-bound to one exact filter/registry pair. Reject a
	// stale server instance even if an attachment ID was later reused.
	if state.filter != s.filter {
		return fmt.Errorf("attachment DNS filter sink is stale")
	}
	if floor := s.server.dnsMinFilterTTL; ttl < floor {
		ttl = floor
	}
	err = s.reg.addDNS(s.filter, cidr, listAllow, ttl, s.server.now())
	if err == nil {
		return nil
	}
	if isMapFull(err) {
		now := s.server.now().UnixNano()
		last := s.lastMapFullWarn.Load()
		if now-last >= int64(mapFullWarnInterval) && s.lastMapFullWarn.CompareAndSwap(last, now) {
			s.logger.Warn().Err(err).
				Str("cidr", cidr.String()).
				Uint64("map_full_drops", s.reg.mapFullCount()).
				Msg("filter rule map full, DNS-resolved IPs are NOT being added (raise filter.max_rule_entries or reduce rule volume)")
		}
	} else {
		s.logger.Warn().Err(err).Str("cidr", cidr.String()).Msg("failed to add DNS-resolved IP to filter")
	}
	return err
}
