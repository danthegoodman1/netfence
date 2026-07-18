package daemon

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"strings"

	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/danthegoodman1/netfence/internal/config"
)

// ControlPlaneCreds carries the resolved gRPC credentials for the
// control-plane connection. They are built once at startup by
// BuildControlPlaneCreds so bad cert/key/CA config surfaces as a clear
// startup error rather than a log line on every reconnect. A nil value (as
// unit tests that never dial pass) is tolerated by the client constructor;
// connect() refuses to dial without a transport credential.
type ControlPlaneCreds struct {
	Transport credentials.TransportCredentials
	PerRPC    credentials.PerRPCCredentials
}

// BuildControlPlaneCreds resolves config.ControlPlaneConfig into gRPC
// credentials. It fails closed: if neither TLS nor the explicit
// `insecure: true` opt-in is configured, it returns an error instead of
// defaulting to plaintext (config.Validate enforces the same invariant
// earlier, at load time).
func BuildControlPlaneCreds(cfg config.ControlPlaneConfig) (*ControlPlaneCreds, error) {
	creds := &ControlPlaneCreds{}

	switch {
	case cfg.Insecure && cfg.TLS != nil:
		return nil, fmt.Errorf("control_plane.tls and control_plane.insecure are mutually exclusive")
	case cfg.Insecure:
		creds.Transport = insecure.NewCredentials()
	case cfg.TLS != nil:
		tlsCfg, err := buildControlPlaneTLSConfig(cfg.TLS)
		if err != nil {
			return nil, err
		}
		creds.Transport = credentials.NewTLS(tlsCfg)
	default:
		return nil, fmt.Errorf("control plane transport security not configured: set control_plane.tls or explicitly opt into plaintext with control_plane.insecure: true")
	}

	if cfg.AuthToken != "" {
		// The token rides as per-RPC metadata. RequireTransportSecurity is
		// true unless the operator explicitly opted into plaintext, so a
		// misconfiguration can never silently leak the token over an
		// unencrypted channel.
		creds.PerRPC = bearerTokenCreds{token: cfg.AuthToken, allowInsecure: cfg.Insecure}
	}

	return creds, nil
}

func buildControlPlaneTLSConfig(cfg *config.ControlPlaneTLSConfig) (*tls.Config, error) {
	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
		ServerName: cfg.ServerName,
	}

	// Empty CA leaves RootCAs nil = system root pool.
	if cfg.CA != "" {
		caPEM, err := readPEMOrFile(cfg.CA)
		if err != nil {
			return nil, fmt.Errorf("reading control_plane.tls.ca: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, fmt.Errorf("control_plane.tls.ca: no valid PEM certificates found")
		}
		tlsCfg.RootCAs = pool
	}

	if (cfg.Cert == "") != (cfg.Key == "") {
		return nil, fmt.Errorf("control_plane.tls.cert and control_plane.tls.key must be set together (both present enables mTLS)")
	}
	if cfg.Cert != "" {
		certPEM, err := readPEMOrFile(cfg.Cert)
		if err != nil {
			return nil, fmt.Errorf("reading control_plane.tls.cert: %w", err)
		}
		keyPEM, err := readPEMOrFile(cfg.Key)
		if err != nil {
			return nil, fmt.Errorf("reading control_plane.tls.key: %w", err)
		}
		clientCert, err := tls.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			return nil, fmt.Errorf("loading control_plane.tls client certificate: %w", err)
		}
		tlsCfg.Certificates = []tls.Certificate{clientCert}
	}

	return tlsCfg, nil
}

// readPEMOrFile accepts either inline PEM (detected by a BEGIN marker) or a
// filesystem path. A value that is neither valid inline PEM nor a plausible
// path (multi-line, or implausibly long) is rejected WITHOUT echoing the
// value, so mis-pasted key material never lands in a startup error message.
func readPEMOrFile(v string) ([]byte, error) {
	if strings.Contains(v, "-----BEGIN") {
		return []byte(v), nil
	}
	if strings.ContainsAny(v, "\r\n") || len(v) > 4096 {
		return nil, fmt.Errorf("value is not a filesystem path and is not valid inline PEM (missing -----BEGIN marker?)")
	}
	return os.ReadFile(v)
}

// bearerTokenCreds attaches `authorization: Bearer <token>` metadata to
// every control-plane RPC.
type bearerTokenCreds struct {
	token         string
	allowInsecure bool
}

func (b bearerTokenCreds) GetRequestMetadata(_ context.Context, _ ...string) (map[string]string, error) {
	return map[string]string{"authorization": "Bearer " + b.token}, nil
}

// RequireTransportSecurity makes gRPC refuse to send the token over an
// unencrypted channel unless the operator explicitly configured
// `insecure: true`.
func (b bearerTokenCreds) RequireTransportSecurity() bool {
	return !b.allowInsecure
}
