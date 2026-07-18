//go:build linux

package integration

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/metadata"

	"github.com/danthegoodman1/netfence/internal/config"
	"github.com/danthegoodman1/netfence/internal/daemon"
	"github.com/danthegoodman1/netfence/internal/store"
	apiv1 "github.com/danthegoodman1/netfence/v1"
)

const tlsTestServerName = "netfence-test-cp"

// testCA is an in-memory certificate authority generated at test runtime —
// no key material is ever committed to the repo.
type testCA struct {
	cert    *x509.Certificate
	key     *ecdsa.PrivateKey
	certPEM []byte
}

func newTestCA(t *testing.T, cn string) *testCA {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	return &testCA{
		cert:    cert,
		key:     key,
		certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
	}
}

// issue signs a leaf certificate with the CA and returns cert+key PEM.
func (ca *testCA) issue(t *testing.T, cn string, dnsNames []string, usage x509.ExtKeyUsage) (certPEM, keyPEM []byte) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{usage},
		DNSNames:     dnsNames,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	require.NoError(t, err)

	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
}

func writePEMFile(t *testing.T, dir, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(path, data, 0600))
	return path
}

// authRecorder captures the authorization metadata of every inbound stream
// so tests can assert the bearer token arrived server side.
type authRecorder struct {
	mu     sync.Mutex
	tokens []string
}

func (a *authRecorder) intercept(srv any, ss grpc.ServerStream, _ *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
	if md, ok := metadata.FromIncomingContext(ss.Context()); ok {
		a.mu.Lock()
		a.tokens = append(a.tokens, md.Get("authorization")...)
		a.mu.Unlock()
	}
	return handler(srv, ss)
}

func (a *authRecorder) sawToken(token string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, got := range a.tokens {
		if got == token {
			return true
		}
	}
	return false
}

// startControlPlaneServer starts the in-process test control plane, with
// optional server-side TLS and stream interception. Returns the CP, the
// listen address, and a stop func.
func startControlPlaneServer(t *testing.T, serverTLS *tls.Config, rec *authRecorder) (*testControlPlane, string, func()) {
	t.Helper()

	cp := newTestControlPlane()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	// Permit the daemon's keepalive ping cadence (the documented CP-side
	// contract): the default gRPC enforcement policy (5min) would GOAWAY
	// the daemon with "too_many_pings".
	opts := []grpc.ServerOption{grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{
		MinTime:             time.Second,
		PermitWithoutStream: true,
	})}
	if serverTLS != nil {
		opts = append(opts, grpc.Creds(credentials.NewTLS(serverTLS)))
	}
	if rec != nil {
		opts = append(opts, grpc.StreamInterceptor(rec.intercept))
	}

	grpcServer := grpc.NewServer(opts...)
	apiv1.RegisterControlPlaneServer(grpcServer, cp)
	go grpcServer.Serve(listener)

	return cp, listener.Addr().String(), grpcServer.Stop
}

// startTLSClient validates cpCfg, builds credentials from it (the exact
// production path: config.Validate + BuildControlPlaneCreds), and runs a
// control-plane client against addr. Returns the client; cleanup is
// registered on t.
func startTLSClient(t *testing.T, addr string, cpCfg config.ControlPlaneConfig) *daemon.ControlPlaneClient {
	t.Helper()

	cfg := &config.Config{
		DNS: config.DNSConfig{
			ListenAddr: "127.0.0.1",
			PortMin:    21000,
			PortMax:    21500,
			Upstream:   "8.8.8.8:53",
		},
		ControlPlane: cpCfg,
	}
	require.NoError(t, cfg.Validate(), "test config must pass the production Validate")

	st, err := store.New(":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { st.Close() })

	logger := zerolog.New(io.Discard)

	srv, err := daemon.NewServer(cfg, st, logger, "test")
	require.NoError(t, err)

	creds, err := daemon.BuildControlPlaneCreds(cfg.ControlPlane)
	require.NoError(t, err)

	cpClient := daemon.NewControlPlaneClient(addr, srv, logger, nil, cfg.ControlPlane.SubscribeAckTimeout, creds)
	// Same wiring as production start.go: zero values keep the defaults.
	cpClient.SetTransportTuning(cfg.ControlPlane.KeepaliveTime, cfg.ControlPlane.KeepaliveTimeout, cfg.ControlPlane.ReconnectBackoffMax)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go cpClient.Run(ctx)

	return cpClient
}

// TestControlPlane_MTLS is the 4A headline test: the daemon dials the
// control plane over mutual TLS — it verifies the server against the
// configured CA (and server_name) and presents its own client certificate,
// which the server requires and verifies — then completes a full
// Subscribe → SubscribedAck handshake, and sends its bearer token.
func TestControlPlane_MTLS(t *testing.T) {
	ca := newTestCA(t, "netfence-test-ca")
	serverCertPEM, serverKeyPEM := ca.issue(t, tlsTestServerName, []string{tlsTestServerName}, x509.ExtKeyUsageServerAuth)
	clientCertPEM, clientKeyPEM := ca.issue(t, "netfence-daemon", nil, x509.ExtKeyUsageClientAuth)

	serverCert, err := tls.X509KeyPair(serverCertPEM, serverKeyPEM)
	require.NoError(t, err)
	clientCAPool := x509.NewCertPool()
	require.True(t, clientCAPool.AppendCertsFromPEM(ca.certPEM))

	rec := &authRecorder{}
	cp, addr, stop := startControlPlaneServer(t, &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientCAs:    clientCAPool,
		ClientAuth:   tls.RequireAndVerifyClientCert, // success proves the daemon presented a valid client cert
		MinVersion:   tls.VersionTLS12,
	}, rec)
	defer stop()

	dir := t.TempDir()
	cpClient := startTLSClient(t, addr, config.ControlPlaneConfig{
		URL: addr,
		TLS: &config.ControlPlaneTLSConfig{
			CA:         writePEMFile(t, dir, "ca.pem", ca.certPEM),
			Cert:       writePEMFile(t, dir, "client.pem", clientCertPEM),
			Key:        writePEMFile(t, dir, "client.key", clientKeyPEM),
			ServerName: tlsTestServerName,
		},
		AuthToken:           "mtls-test-token",
		SubscribeAckTimeout: 5 * time.Second,
	})

	require.Eventually(t, func() bool {
		return cpClient.State() == apiv1.ConnectionState_CONNECTION_STATE_CONNECTED
	}, 5*time.Second, 50*time.Millisecond, "daemon should connect over mTLS")

	// Full Subscribe → SubscribedAck round trip over the mTLS stream.
	cp.SetConfig("mtls-target", &apiv1.SubscribedAck{Mode: apiv1.PolicyMode_POLICY_MODE_DISABLED})
	ack, err := cpClient.SubscribeAndWait(context.Background(), &apiv1.Subscribed{
		Id:     "mtls-attachment",
		Target: "mtls-target",
		Type:   apiv1.AttachmentType_ATTACHMENT_TYPE_CGROUP,
	})
	require.NoError(t, err, "Subscribe should be acked over the mTLS stream")
	require.NotNil(t, ack)
	require.Equal(t, apiv1.PolicyMode_POLICY_MODE_DISABLED, ack.Mode)

	require.True(t, rec.sawToken("Bearer mtls-test-token"),
		"control plane should have received the configured bearer token")
}

// TestControlPlane_TLS_RejectsUntrustedServerCert: a server whose
// certificate is NOT signed by the daemon's configured CA (i.e. a MITM with
// its own cert) must never get a connection — no rules can flow.
func TestControlPlane_TLS_RejectsUntrustedServerCert(t *testing.T) {
	trustedCA := newTestCA(t, "netfence-trusted-ca")
	attackerCA := newTestCA(t, "netfence-attacker-ca")

	// The server presents a cert signed by the attacker CA.
	serverCertPEM, serverKeyPEM := attackerCA.issue(t, tlsTestServerName, []string{tlsTestServerName}, x509.ExtKeyUsageServerAuth)
	serverCert, err := tls.X509KeyPair(serverCertPEM, serverKeyPEM)
	require.NoError(t, err)

	_, addr, stop := startControlPlaneServer(t, &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		MinVersion:   tls.VersionTLS12,
	}, nil)
	defer stop()

	// The daemon trusts only trustedCA.
	dir := t.TempDir()
	cpClient := startTLSClient(t, addr, config.ControlPlaneConfig{
		URL: addr,
		TLS: &config.ControlPlaneTLSConfig{
			CA:         writePEMFile(t, dir, "ca.pem", trustedCA.certPEM),
			ServerName: tlsTestServerName,
		},
		SubscribeAckTimeout: time.Second,
	})

	require.Never(t, func() bool {
		return cpClient.State() == apiv1.ConnectionState_CONNECTION_STATE_CONNECTED
	}, 3*time.Second, 50*time.Millisecond, "daemon must not connect to a server signed by an untrusted CA")
}

// TestControlPlane_TLS_RejectsWrongServerName: the daemon must verify the
// server certificate against the configured server_name.
func TestControlPlane_TLS_RejectsWrongServerName(t *testing.T) {
	ca := newTestCA(t, "netfence-test-ca")
	serverCertPEM, serverKeyPEM := ca.issue(t, tlsTestServerName, []string{tlsTestServerName}, x509.ExtKeyUsageServerAuth)
	serverCert, err := tls.X509KeyPair(serverCertPEM, serverKeyPEM)
	require.NoError(t, err)

	_, addr, stop := startControlPlaneServer(t, &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		MinVersion:   tls.VersionTLS12,
	}, nil)
	defer stop()

	cpClient := startTLSClient(t, addr, config.ControlPlaneConfig{
		URL: addr,
		TLS: &config.ControlPlaneTLSConfig{
			CA:         string(ca.certPEM), // inline PEM path of the loader
			ServerName: "wrong.example.com",
		},
		SubscribeAckTimeout: time.Second,
	})

	require.Never(t, func() bool {
		return cpClient.State() == apiv1.ConnectionState_CONNECTION_STATE_CONNECTED
	}, 3*time.Second, 50*time.Millisecond, "daemon must not connect when server_name does not match the certificate")
}

// TestControlPlane_TLS_RejectsPlaintextControlPlane is the MITM
// discriminator: a daemon configured for TLS must refuse a plaintext
// control plane (pre-4A, the hardcoded insecure credentials would happily
// connect to it).
func TestControlPlane_TLS_RejectsPlaintextControlPlane(t *testing.T) {
	ca := newTestCA(t, "netfence-test-ca")

	// Plaintext control plane — no TLS at all.
	_, addr, stop := startControlPlaneServer(t, nil, nil)
	defer stop()

	cpClient := startTLSClient(t, addr, config.ControlPlaneConfig{
		URL: addr,
		TLS: &config.ControlPlaneTLSConfig{
			CA:         string(ca.certPEM),
			ServerName: tlsTestServerName,
		},
		SubscribeAckTimeout: time.Second,
	})

	require.Never(t, func() bool {
		return cpClient.State() == apiv1.ConnectionState_CONNECTION_STATE_CONNECTED
	}, 3*time.Second, 50*time.Millisecond, "TLS-configured daemon must not fall back to a plaintext control plane")
}

// TestControlPlane_ExplicitInsecureOptIn: `insecure: true` remains a
// working, explicit opt-in for local/dev setups.
func TestControlPlane_ExplicitInsecureOptIn(t *testing.T) {
	cp, addr, stop := startControlPlaneServer(t, nil, nil)
	defer stop()

	cpClient := startTLSClient(t, addr, config.ControlPlaneConfig{
		URL:                 addr,
		Insecure:            true,
		SubscribeAckTimeout: 5 * time.Second,
	})

	require.Eventually(t, func() bool {
		return cpClient.State() == apiv1.ConnectionState_CONNECTION_STATE_CONNECTED
	}, 5*time.Second, 50*time.Millisecond, "explicit insecure opt-in should still connect")

	cp.SetConfig("insecure-target", &apiv1.SubscribedAck{Mode: apiv1.PolicyMode_POLICY_MODE_DISABLED})
	ack, err := cpClient.SubscribeAndWait(context.Background(), &apiv1.Subscribed{
		Id:     "insecure-attachment",
		Target: "insecure-target",
		Type:   apiv1.AttachmentType_ATTACHMENT_TYPE_CGROUP,
	})
	require.NoError(t, err)
	require.NotNil(t, ack)
}
