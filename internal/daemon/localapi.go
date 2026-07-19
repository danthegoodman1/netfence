package daemon

import (
	"context"
	"errors"
	"fmt"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/danthegoodman1/netfence/pkg/filter"
	apiv1 "github.com/danthegoodman1/netfence/v1"
)

var errInvalidPolicyCommand = errors.New("invalid policy command")

type preparedPolicyCommand struct {
	id    string
	apply func(*Server) error
}

func invalidPolicyCommandf(format string, args ...any) error {
	return fmt.Errorf("%w: %s", errInvalidPolicyCommand, fmt.Sprintf(format, args...))
}

// preparePolicyCommand validates and canonicalizes every policy mutation
// field without entering attachment mutation admission. Both the control-plane
// stream and local unary RPC use the resulting dispatcher closure.
func (s *Server) preparePolicyCommand(cmd *apiv1.ControlCommand) (*preparedPolicyCommand, error) {
	if cmd == nil {
		return nil, invalidPolicyCommandf("command is required")
	}
	if cmd.Id == "" {
		return nil, invalidPolicyCommandf("attachment id is required")
	}
	prepared := &preparedPolicyCommand{id: cmd.Id}
	switch value := cmd.Command.(type) {
	case *apiv1.ControlCommand_SetMode:
		if value.SetMode == nil {
			return nil, invalidPolicyCommandf("set_mode payload is required")
		}
		mode := value.SetMode.Mode
		if err := validatePolicyMode(mode); err != nil {
			return nil, invalidPolicyCommandf("%v", err)
		}
		prepared.apply = func(server *Server) error {
			return server.SetFilterMode(cmd.Id, mode)
		}

	case *apiv1.ControlCommand_AllowCidr:
		cidr, ttl, err := parseIncrementalCIDREntry(value.AllowCidr)
		if err != nil {
			return nil, invalidPolicyCommandf("validating allow CIDR: %v", err)
		}
		prepared.apply = func(server *Server) error {
			return server.AllowCIDR(cmd.Id, cidr, ttl)
		}

	case *apiv1.ControlCommand_DenyCidr:
		cidr, ttl, err := parseIncrementalCIDREntry(value.DenyCidr)
		if err != nil {
			return nil, invalidPolicyCommandf("validating deny CIDR: %v", err)
		}
		prepared.apply = func(server *Server) error {
			return server.DenyCIDR(cmd.Id, cidr, ttl)
		}

	case *apiv1.ControlCommand_RemoveCidr:
		if err := validateRuleList(cmd.RemoveCidrList); err != nil {
			return nil, invalidPolicyCommandf("%v", err)
		}
		cidr, err := filter.ParseCIDR(value.RemoveCidr)
		if err != nil {
			return nil, invalidPolicyCommandf("parsing remove CIDR %q: %v", value.RemoveCidr, err)
		}
		list := cmd.RemoveCidrList
		prepared.apply = func(server *Server) error {
			return server.RemoveCIDRRule(cmd.Id, cidr, list)
		}

	case *apiv1.ControlCommand_BulkUpdate:
		bulk, err := s.prepareBulkUpdate(cmd.Id, value.BulkUpdate)
		if err != nil {
			if errors.Is(err, errAttachmentUnavailable) {
				return nil, err
			}
			return nil, invalidPolicyCommandf("validating bulk update: %v", err)
		}
		prepared.apply = func(server *Server) error {
			return server.applyPreparedRules(cmd.Id, bulk)
		}

	case *apiv1.ControlCommand_SetDnsMode:
		if value.SetDnsMode == nil {
			return nil, invalidPolicyCommandf("set_dns_mode payload is required")
		}
		mode := value.SetDnsMode.Mode
		if err := validateDNSMode(mode); err != nil {
			return nil, invalidPolicyCommandf("%v", err)
		}
		prepared.apply = func(server *Server) error {
			return server.SetDnsMode(cmd.Id, mode)
		}

	case *apiv1.ControlCommand_AllowDomain:
		if value.AllowDomain == nil {
			return nil, invalidPolicyCommandf("allow_domain payload is required")
		}
		domain, err := validateAndNormalizeDomain(value.AllowDomain.Domain)
		if err != nil {
			return nil, invalidPolicyCommandf("validating allow domain: %v", err)
		}
		include := value.AllowDomain.IncludeSubdomains
		prepared.apply = func(server *Server) error {
			return server.AllowDomain(cmd.Id, domain, include)
		}

	case *apiv1.ControlCommand_DenyDomain:
		if value.DenyDomain == nil {
			return nil, invalidPolicyCommandf("deny_domain payload is required")
		}
		domain, err := validateAndNormalizeDomain(value.DenyDomain.Domain)
		if err != nil {
			return nil, invalidPolicyCommandf("validating deny domain: %v", err)
		}
		include := value.DenyDomain.IncludeSubdomains
		prepared.apply = func(server *Server) error {
			return server.DenyDomain(cmd.Id, domain, include)
		}

	case *apiv1.ControlCommand_RemoveDomain:
		domain, err := validateAndNormalizeDomain(value.RemoveDomain)
		if err != nil {
			return nil, invalidPolicyCommandf("validating remove domain: %v", err)
		}
		prepared.apply = func(server *Server) error {
			return server.RemoveDomain(cmd.Id, domain)
		}

	case *apiv1.ControlCommand_SyncAck:
		return nil, invalidPolicyCommandf("sync_ack is not a policy mutation")
	case *apiv1.ControlCommand_SubscribedAck:
		return nil, invalidPolicyCommandf("subscribed_ack is not a local policy mutation; use bulk_update")
	case nil:
		return nil, invalidPolicyCommandf("command variant is required")
	default:
		return nil, invalidPolicyCommandf("unsupported command variant %T", value)
	}
	return prepared, nil
}

func validateRuleList(list apiv1.RuleList) error {
	switch list {
	case apiv1.RuleList_RULE_LIST_UNSPECIFIED,
		apiv1.RuleList_RULE_LIST_ALLOW,
		apiv1.RuleList_RULE_LIST_DENY,
		apiv1.RuleList_RULE_LIST_BOTH:
		return nil
	default:
		return fmt.Errorf("invalid CIDR rule list: %d", list)
	}
}

// ApplyPolicyCommand is the shared pure policy dispatcher. Stream-specific
// acks, epochs, admission shutdown, result events, and logging stay in the
// control-plane client; this method only validates and applies policy.
func (s *Server) ApplyPolicyCommand(cmd *apiv1.ControlCommand) error {
	prepared, err := s.preparePolicyCommand(cmd)
	if err != nil {
		return err
	}
	return prepared.apply(s)
}

func (s *Server) requireLocalAttachmentReady(id string) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	state := s.attachments[id]
	if state == nil {
		return status.Errorf(codes.NotFound, "attachment not found: %s", id)
	}
	if state.cleanupNeeded || state.mutationsClosed {
		return status.Errorf(codes.FailedPrecondition, "attachment is unavailable: %s", id)
	}
	if state.setupDone == nil {
		return nil
	}
	select {
	case <-state.setupDone:
		if state.setupCommitted.Load() {
			return nil
		}
		return status.Errorf(codes.FailedPrecondition, "attachment setup did not commit: %s", id)
	default:
		return status.Errorf(codes.FailedPrecondition, "attachment setup is still in progress: %s", id)
	}
}

// ApplyCommand is the sole local mutation RPC. command_id is rejected because
// CommandResult exists only on the control-plane stream; unary RPC status is
// the local caller's exact outcome.
func (s *Server) ApplyCommand(ctx context.Context, cmd *apiv1.ControlCommand) (*emptypb.Empty, error) {
	if err := ctx.Err(); err != nil {
		return nil, status.FromContextError(err).Err()
	}
	if cmd != nil && cmd.CommandId != "" {
		return nil, status.Error(codes.InvalidArgument, "command_id is not accepted by the local unary API")
	}
	prepared, err := s.preparePolicyCommand(cmd)
	if err != nil {
		if errors.Is(err, errInvalidPolicyCommand) {
			return nil, status.Error(codes.InvalidArgument, err.Error())
		}
		if errors.Is(err, errAttachmentUnavailable) {
			return nil, status.Error(codes.NotFound, err.Error())
		}
		return nil, err
	}
	if err := s.requireLocalAttachmentReady(prepared.id); err != nil {
		return nil, err
	}
	done, ok := s.beginControlCommand(prepared.id)
	if !ok {
		return nil, status.Error(codes.Unavailable, "daemon is stopping")
	}
	defer done()
	if err := prepared.apply(s); err != nil {
		if errors.Is(err, errPolicyDegraded) {
			return nil, status.Error(codes.FailedPrecondition, err.Error())
		}
		return nil, err
	}
	return &emptypb.Empty{}, nil
}

// GetRules serializes one coherent userspace policy snapshot behind the same
// per-attachment mutation barrier as writers. It does not inventory protected
// maps or expose DNS-derived exact-host cache entries.
func (s *Server) GetRules(ctx context.Context, req *apiv1.GetRulesRequest) (*apiv1.GetRulesResponse, error) {
	if err := ctx.Err(); err != nil {
		return nil, status.FromContextError(err).Err()
	}
	if req == nil || req.Id == "" {
		return nil, status.Error(codes.InvalidArgument, "attachment id is required")
	}
	if err := s.requireLocalAttachmentReady(req.Id); err != nil {
		return nil, err
	}
	drainDone, ok := s.beginControlCommand(req.Id)
	if !ok {
		return nil, status.Error(codes.Unavailable, "daemon is stopping")
	}
	defer drainDone()
	state, mutationDone, err := s.beginAttachmentMutation(req.Id)
	if err != nil {
		return nil, err
	}
	defer mutationDone()

	s.mu.RLock()
	if s.attachments[req.Id] != state {
		s.mu.RUnlock()
		return nil, status.Error(codes.NotFound, "attachment changed while inspecting rules")
	}
	mode := parsePolicyMode(state.info.Mode)
	degradedReason := state.info.PolicyDegradedReason
	s.mu.RUnlock()

	response := &apiv1.GetRulesResponse{
		Id:                   req.Id,
		Mode:                 mode,
		PolicyDegraded:       degradedReason != "",
		PolicyDegradedReason: degradedReason,
		Dns:                  &apiv1.DnsConfig{Mode: apiv1.DnsMode_DNS_MODE_DISABLED},
	}
	for _, rule := range state.ttls.snapshotRules() {
		item := &apiv1.CIDRRule{
			Cidr:        rule.cidr,
			PolicyOwned: rule.policyOwned,
			SystemOwned: rule.systemOwned,
			Provisional: rule.provisional,
			Installed:   rule.installed,
		}
		if rule.list == listAllow {
			item.List = apiv1.RuleList_RULE_LIST_ALLOW
		} else {
			item.List = apiv1.RuleList_RULE_LIST_DENY
		}
		if !rule.expiresAt.IsZero() {
			item.ExpiresAt = timestamppb.New(rule.expiresAt)
		}
		response.Cidrs = append(response.Cidrs, item)
	}
	if state.dns != nil {
		state.dns.mu.RLock()
		response.Dns = state.dns.currentConfigLocked()
		state.dns.mu.RUnlock()
	}
	return response, nil
}
