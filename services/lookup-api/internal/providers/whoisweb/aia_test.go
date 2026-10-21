package whoisweb

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func issue(t *testing.T, template *x509.Certificate, parent *testCA) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, parentCert := key, template
	if parent != nil {
		signer, parentCert = parent.key, parent.cert
	}
	der, err := x509.CreateCertificate(rand.Reader, template, parentCert, &key.PublicKey, signer)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &testCA{cert: cert, key: key}
}

// A server that omits its intermediate is accepted once the intermediate is
// fetched from the leaf's AIA URL, and still rejected for a wrong name.
func TestAIAVerifierCompletesMissingIntermediate(t *testing.T) {
	now := time.Now()
	root := issue(t, &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test Root"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}, nil)
	inter := issue(t, &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "Test Intermediate"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}, root)
	leaf := issue(t, &x509.Certificate{SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "127.0.0.1"}, DNSNames: []string{"registry.test"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IssuingCertificateURL: []string{"http://aia.test/inter.cer"}}, inter)

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{leaf.cert.Raw}, PrivateKey: leaf.key}}}
	server.StartTLS()
	defer server.Close()

	roots := x509.NewCertPool()
	roots.AddCert(root.cert)
	fetched := 0
	client := func(serverName string, fetch bool) *http.Client {
		verifier := &aiaVerifier{cache: map[string]*x509.Certificate{}, roots: roots}
		verifier.fetch = func(context.Context, string) (*x509.Certificate, error) {
			if !fetch {
				return nil, errors.New("no AIA")
			}
			fetched++
			return inter.cert, nil
		}
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true, ServerName: serverName, VerifyConnection: verifier.verify}
		return &http.Client{Transport: transport}
	}

	if _, err := client("registry.test", false).Get(server.URL); err == nil {
		t.Fatal("expected the incomplete chain to fail without AIA")
	}
	resp, err := client("registry.test", true).Get(server.URL)
	if err != nil {
		t.Fatalf("expected AIA to complete the chain: %v", err)
	}
	resp.Body.Close()
	if fetched != 1 {
		t.Fatalf("expected one AIA fetch, got %d", fetched)
	}
	if _, err := client("other.test", true).Get(server.URL); err == nil {
		t.Fatal("expected a name mismatch to fail even with AIA")
	}
}
