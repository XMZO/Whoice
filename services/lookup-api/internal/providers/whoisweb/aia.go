package whoisweb

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/xmzo/whoice/services/lookup-api/internal/security"
)

// Some registry servers (api.nic.dz, nic.pa) send their leaf certificate
// without the intermediate. Browsers fill the gap from the certificate's
// Authority Information Access URL; this client does the same. The chain is
// still verified in full, against the system roots and the server name; only
// the missing intermediates come from AIA.

const (
	aiaMaxDepth   = 3
	aiaFetchLimit = 64 * 1024
	aiaTimeout    = 5 * time.Second
)

type aiaVerifier struct {
	mu     sync.Mutex
	cache  map[string]*x509.Certificate
	fetch  func(ctx context.Context, url string) (*x509.Certificate, error)
	policy security.ServerPolicy
	roots  *x509.CertPool
}

func newAIAClient() *http.Client {
	verifier := &aiaVerifier{cache: map[string]*x509.Certificate{}, policy: security.NewServerPolicy(false)}
	verifier.fetch = verifier.download
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{
		// Verification is not skipped: VerifyConnection checks the chain and
		// the server name itself, so it can add intermediates fetched by AIA.
		InsecureSkipVerify: true,
		VerifyConnection:   verifier.verify,
	}
	return &http.Client{Transport: transport}
}

func (v *aiaVerifier) verify(state tls.ConnectionState) error {
	if len(state.PeerCertificates) == 0 {
		return errors.New("tls: server sent no certificate")
	}
	if state.ServerName == "" {
		// Without a name the hostname check below would be skipped.
		return errors.New("tls: no server name to verify")
	}
	leaf := state.PeerCertificates[0]
	intermediates := x509.NewCertPool()
	for _, cert := range state.PeerCertificates[1:] {
		intermediates.AddCert(cert)
	}
	opts := x509.VerifyOptions{DNSName: state.ServerName, Roots: v.roots, Intermediates: intermediates}
	_, err := leaf.Verify(opts)
	var unknown x509.UnknownAuthorityError
	if err == nil || !errors.As(err, &unknown) {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), aiaTimeout)
	defer cancel()
	cert := leaf
	for depth := 0; depth < aiaMaxDepth; depth++ {
		issuer := v.issuerOf(ctx, cert)
		if issuer == nil {
			break
		}
		intermediates.AddCert(issuer)
		if _, retry := leaf.Verify(opts); retry == nil {
			return nil
		}
		cert = issuer
	}
	return err
}

// issuerOf returns the first certificate reachable from cert's AIA issuer URLs.
func (v *aiaVerifier) issuerOf(ctx context.Context, cert *x509.Certificate) *x509.Certificate {
	for _, url := range cert.IssuingCertificateURL {
		v.mu.Lock()
		cached := v.cache[url]
		v.mu.Unlock()
		if cached != nil {
			return cached
		}
		issuer, err := v.fetch(ctx, url)
		if err != nil || cert.CheckSignatureFrom(issuer) != nil {
			continue
		}
		v.mu.Lock()
		v.cache[url] = issuer
		v.mu.Unlock()
		return issuer
	}
	return nil
}

func (v *aiaVerifier) download(ctx context.Context, url string) (*x509.Certificate, error) {
	if err := v.policy.AllowRDAP(ctx, url); err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("AIA issuer download failed")
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, aiaFetchLimit))
	if err != nil {
		return nil, err
	}
	if block, _ := pem.Decode(body); block != nil {
		body = block.Bytes
	}
	return x509.ParseCertificate(body)
}
