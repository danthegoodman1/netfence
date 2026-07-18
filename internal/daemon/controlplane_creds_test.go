package daemon

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/danthegoodman1/netfence/internal/config"
)

// genSelfSignedPEM returns a self-signed cert and key as PEM for creds
// builder tests (validity of the chain is not exercised here, only loading).
func genSelfSignedPEM(t *testing.T) (certPEM, keyPEM []byte) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "netfence-creds-test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating certificate: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshaling key: %v", err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM
}

func writeTempFile(t *testing.T, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatalf("writing %s: %v", name, err)
	}
	return path
}

func TestBuildControlPlaneCreds_Insecure(t *testing.T) {
	creds, err := BuildControlPlaneCreds(config.ControlPlaneConfig{URL: "localhost:9000", Insecure: true})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := creds.Transport.Info().SecurityProtocol; got != "insecure" {
		t.Fatalf("expected insecure transport, got %q", got)
	}
	if creds.PerRPC != nil {
		t.Fatal("expected no per-RPC creds without auth_token")
	}
}

// TestBuildControlPlaneCreds_FailClosed asserts the builder itself refuses
// to produce credentials when neither tls nor insecure is configured — no
// silent plaintext fallback even if config validation were bypassed.
func TestBuildControlPlaneCreds_FailClosed(t *testing.T) {
	_, err := BuildControlPlaneCreds(config.ControlPlaneConfig{URL: "cp.example.com:443"})
	if err == nil {
		t.Fatal("expected error for URL without tls or insecure, got nil")
	}
	if !strings.Contains(err.Error(), "control_plane.tls") || !strings.Contains(err.Error(), "insecure") {
		t.Fatalf("error should name both remediation keys, got %q", err)
	}
}

func TestBuildControlPlaneCreds_TLSServerOnly(t *testing.T) {
	caPEM, _ := genSelfSignedPEM(t)

	t.Run("ca from file", func(t *testing.T) {
		caFile := writeTempFile(t, "ca.pem", caPEM)
		creds, err := BuildControlPlaneCreds(config.ControlPlaneConfig{
			URL: "cp.example.com:443",
			TLS: &config.ControlPlaneTLSConfig{CA: caFile, ServerName: "cp.internal"},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got := creds.Transport.Info().SecurityProtocol; got != "tls" {
			t.Fatalf("expected tls transport, got %q", got)
		}
	})

	t.Run("ca inline PEM", func(t *testing.T) {
		creds, err := BuildControlPlaneCreds(config.ControlPlaneConfig{
			URL: "cp.example.com:443",
			TLS: &config.ControlPlaneTLSConfig{CA: string(caPEM)},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got := creds.Transport.Info().SecurityProtocol; got != "tls" {
			t.Fatalf("expected tls transport, got %q", got)
		}
	})

	t.Run("empty tls block uses system roots", func(t *testing.T) {
		creds, err := BuildControlPlaneCreds(config.ControlPlaneConfig{
			URL: "cp.example.com:443",
			TLS: &config.ControlPlaneTLSConfig{},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got := creds.Transport.Info().SecurityProtocol; got != "tls" {
			t.Fatalf("expected tls transport, got %q", got)
		}
	})
}

func TestBuildControlPlaneCreds_MTLSClientCert(t *testing.T) {
	caPEM, _ := genSelfSignedPEM(t)
	certPEM, keyPEM := genSelfSignedPEM(t)

	creds, err := BuildControlPlaneCreds(config.ControlPlaneConfig{
		URL: "cp.example.com:443",
		TLS: &config.ControlPlaneTLSConfig{
			CA:   string(caPEM),
			Cert: writeTempFile(t, "client.pem", certPEM),
			Key:  writeTempFile(t, "client.key", keyPEM),
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := creds.Transport.Info().SecurityProtocol; got != "tls" {
		t.Fatalf("expected tls transport, got %q", got)
	}
}

func TestBuildControlPlaneCreds_TLSErrors(t *testing.T) {
	caPEM, _ := genSelfSignedPEM(t)
	certPEM, keyPEM := genSelfSignedPEM(t)

	tests := []struct {
		name    string
		tls     *config.ControlPlaneTLSConfig
		wantErr string
	}{
		{
			name:    "missing ca file",
			tls:     &config.ControlPlaneTLSConfig{CA: filepath.Join(t.TempDir(), "nope.pem")},
			wantErr: "control_plane.tls.ca",
		},
		{
			name:    "garbage ca content",
			tls:     &config.ControlPlaneTLSConfig{CA: writeTempFile(t, "junk.pem", []byte("not a cert"))},
			wantErr: "no valid PEM certificates",
		},
		{
			name:    "cert without key",
			tls:     &config.ControlPlaneTLSConfig{CA: string(caPEM), Cert: string(certPEM)},
			wantErr: "must be set together",
		},
		{
			name: "unreadable client cert file",
			tls: &config.ControlPlaneTLSConfig{
				CA:   string(caPEM),
				Cert: filepath.Join(t.TempDir(), "missing.pem"),
				Key:  string(keyPEM),
			},
			wantErr: "control_plane.tls.cert",
		},
		{
			name: "mismatched cert and key",
			tls: func() *config.ControlPlaneTLSConfig {
				otherCert, _ := genSelfSignedPEM(t)
				return &config.ControlPlaneTLSConfig{CA: string(caPEM), Cert: string(otherCert), Key: string(keyPEM)}
			}(),
			wantErr: "client certificate",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := BuildControlPlaneCreds(config.ControlPlaneConfig{URL: "cp.example.com:443", TLS: tt.tls})
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("expected error containing %q, got %q", tt.wantErr, err)
			}
		})
	}

	// A mis-pasted headerless key (multi-line, no BEGIN marker) must be
	// rejected WITHOUT the secret material appearing in the error message.
	t.Run("mispasted key material not echoed in error", func(t *testing.T) {
		secret := "MIIEvQIBADANBgkqhkiG9w0BAQ\nEFAKESECRETKEYMATERIAL\nSHOULDNOTAPPEAR"
		_, err := BuildControlPlaneCreds(config.ControlPlaneConfig{
			URL: "cp.example.com:443",
			TLS: &config.ControlPlaneTLSConfig{Key: secret, Cert: string(certPEM)},
		})
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if strings.Contains(err.Error(), "SHOULDNOTAPPEAR") {
			t.Fatalf("error leaked mis-pasted key material: %q", err)
		}
		if !strings.Contains(err.Error(), "inline PEM") {
			t.Fatalf("expected the not-a-path/not-PEM guard error, got %q", err)
		}
	})
}

func TestBuildControlPlaneCreds_BearerToken(t *testing.T) {
	t.Run("requires transport security on tls channel", func(t *testing.T) {
		creds, err := BuildControlPlaneCreds(config.ControlPlaneConfig{
			URL:       "cp.example.com:443",
			TLS:       &config.ControlPlaneTLSConfig{},
			AuthToken: "sekrit",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if creds.PerRPC == nil {
			t.Fatal("expected per-RPC creds for auth_token")
		}
		if !creds.PerRPC.RequireTransportSecurity() {
			t.Fatal("token must require transport security when channel is not explicitly insecure")
		}
		md, err := creds.PerRPC.GetRequestMetadata(context.Background())
		if err != nil {
			t.Fatalf("GetRequestMetadata: %v", err)
		}
		if md["authorization"] != "Bearer sekrit" {
			t.Fatalf("expected bearer token metadata, got %v", md)
		}
	})

	t.Run("explicit insecure permits plaintext token", func(t *testing.T) {
		creds, err := BuildControlPlaneCreds(config.ControlPlaneConfig{
			URL:       "localhost:9000",
			Insecure:  true,
			AuthToken: "sekrit",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if creds.PerRPC == nil {
			t.Fatal("expected per-RPC creds for auth_token")
		}
		if creds.PerRPC.RequireTransportSecurity() {
			t.Fatal("explicit insecure opt-in should permit the token on a plaintext channel")
		}
	})
}
