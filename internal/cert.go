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

type Certificate struct {
	cert     *x509.Certificate
	chain    map[string]*Certificate
	hostname string
}

func NewCertificate(cert *x509.Certificate) *Certificate {
	return &Certificate{
		cert:  cert,
		chain: map[string]*Certificate{},
	}
}

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

func (c *Certificate) DownloadIssuingCertificate() {
	if len(c.cert.IssuingCertificateURL) == 0 {
		return
	}

	for _, rawUrl := range c.cert.IssuingCertificateURL {
		u, err := url.Parse(rawUrl)
		if err != nil {
			continue
		}

		if issuingCert, err := GetCertificate(u); err == nil {
			issuingCert.DownloadIssuingCertificate()
			c.AddCertificateToChain(issuingCert)
		}
	}
}

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

func (c *Certificate) Subject() pkix.Name {
	return c.cert.Subject
}

func (c *Certificate) Issuer() pkix.Name {
	return c.cert.Issuer
}

func (c *Certificate) CommonName() string {
	return c.cert.Subject.CommonName
}

func (c *Certificate) DNSNames() []string {
	return c.cert.DNSNames
}

func (c *Certificate) IPAddresses() []net.IP {
	return c.cert.IPAddresses
}

func (c *Certificate) NotBefore() time.Time {
	return c.cert.NotBefore
}

func (c *Certificate) NotAfter() time.Time {
	return c.cert.NotAfter
}

func (c *Certificate) SignedCertificateTimestamps() []ct.SignedCertificateTimestamp {
	return certutil.GetSCTs(c.cert)
}

func (c *Certificate) SerialNumber() *big.Int {
	return c.cert.SerialNumber
}

func (c *Certificate) IsOCSPPresent() bool {
	return len(c.cert.OCSPServer) > 0
}

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

func (c *Certificate) Equal(other *Certificate) bool {
	return c.cert.Equal(other.cert)
}
