package internal

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"time"

	ct "github.com/google/certificate-transparency-go"
	"github.com/krzysdabro/tlscert/internal/certutil"
)

// Certificate defines a X.509 certificate and its chain.
type Certificate struct {
	cert     *x509.Certificate
	chain    map[string]*Certificate
	hostname string
}

// NewCertificate creates a new certificate.
func NewCertificate(cert *x509.Certificate) *Certificate {
	return &Certificate{
		cert:  cert,
		chain: map[string]*Certificate{},
	}
}

// AddCertificateToChain add another certificate to the chain.
func (c *Certificate) AddCertificateToChain(cert *Certificate) {
	if _, ok := c.chain[cert.Subject().String()]; ok || c.Equal(cert) {
		return
	}

	c.chain[cert.Subject().String()] = cert
}

func (c *Certificate) chainCertPool() *x509.CertPool {
	pool := x509.NewCertPool()
	for _, cert := range c.Chain() {
		pool.AddCert(cert.cert)
	}
	return pool
}

// DownloadIssuingCertificate downloads certificate specified in Authority Information Access.
func (c *Certificate) DownloadIssuingCertificate() {
	if len(c.cert.IssuingCertificateURL) == 0 {
		return
	}

	for _, rawURL := range c.cert.IssuingCertificateURL {
		u, err := url.Parse(rawURL)
		if err != nil {
			continue
		}

		if issuingCert, err := GetCertificate(u); err == nil {
			issuingCert.DownloadIssuingCertificate()
			c.AddCertificateToChain(issuingCert)
		}
	}
}

// IsValid checks certificate validity.
func (c *Certificate) IsValid() bool {
	opts := x509.VerifyOptions{
		Intermediates: c.chainCertPool(),
	}

	if c.hostname != "" {
		opts.DNSName = c.hostname
	}

	_, err := c.cert.Verify(opts)
	return err == nil
}

// Chain returns chain of the certificate.
func (c *Certificate) Chain() map[string]*Certificate {
	certs := c.chain
	for _, chainCert := range c.chain {
		for _, innerChainCert := range chainCert.Chain() {
			if _, ok := certs[innerChainCert.Subject().String()]; !ok {
				certs[innerChainCert.Subject().String()] = innerChainCert
			}
		}
	}

	return certs
}

// Subject returns subject of the certificate.
func (c *Certificate) Subject() pkix.Name {
	return c.cert.Subject
}

// Issuer returns issuer of the certificate.
func (c *Certificate) Issuer() pkix.Name {
	return c.cert.Issuer
}

// CommonName returns common name of the certificate.
func (c *Certificate) CommonName() string {
	return c.cert.Subject.CommonName
}

// DNSNames returns DNS names of the certificate.
func (c *Certificate) DNSNames() []string {
	return c.cert.DNSNames
}

// IPAddresses returns IP addresses of the certificate.
func (c *Certificate) IPAddresses() []net.IP {
	return c.cert.IPAddresses
}

// NotBefore returns lower expiration bound of the certificate.
func (c *Certificate) NotBefore() time.Time {
	return c.cert.NotBefore
}

// NotAfter returns higher expiration bound of the certificate.
func (c *Certificate) NotAfter() time.Time {
	return c.cert.NotAfter
}

// SignedCertificateTimestamps returns SCTs of the certificate.
func (c *Certificate) SignedCertificateTimestamps() []ct.SignedCertificateTimestamp {
	return certutil.GetSCTs(c.cert)
}

// SerialNumber returns the certificate's serial number.
func (c *Certificate) SerialNumber() *big.Int {
	return c.cert.SerialNumber
}

// IsOCSPPresent checks whether the OCSP server URL is present in the certificate.
func (c *Certificate) IsOCSPPresent() bool {
	return len(c.cert.OCSPServer) > 0
}

// OCSPStatus checks validity of the certificate with OCSP server.
func (c *Certificate) OCSPStatus() (bool, error) {
	if !c.IsOCSPPresent() {
		return false, fmt.Errorf("no OCSP server present for certificate")
	}

	issuer, issuerOk := c.chain[c.Issuer().String()]
	if !issuerOk {
		return false, fmt.Errorf("issuer not present in chain")
	}

	if ok, err := certutil.CheckOCSP(c.cert, issuer.cert); err != nil || !ok {
		return false, err
	}

	return true, nil
}

// Equal reports whether the certificates are the same.
func (c *Certificate) Equal(other *Certificate) bool {
	return c.cert.Equal(other.cert)
}
