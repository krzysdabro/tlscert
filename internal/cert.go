package internal

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/crypto/ocsp"
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

func (c *Certificate) IsRevoked() bool {
	if _, issuerOk := c.chain[c.Issuer().String()]; len(c.cert.OCSPServer) == 0 || !issuerOk {
		return false
	}

	body, err := ocsp.CreateRequest(c.cert, c.chain[c.Issuer().String()].cert, nil)
	if err != nil {
		return false
	}

	resp, err := http.Post(c.cert.OCSPServer[0], "application/ocsp-request", bytes.NewReader(body))
	if err != nil || resp.StatusCode != 200 {
		return false
	}

	buf := bytes.NewBuffer([]byte{})
	buf.ReadFrom(resp.Body)

	r, err := ocsp.ParseResponse(buf.Bytes(), c.chain[c.Issuer().String()].cert)
	return err == nil && r.Status == 1
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

func (c *Certificate) SerialNumber() string {
	str := strings.ToUpper(c.cert.SerialNumber.Text(16))
	if len(str)%2 == 1 {
		str = "0" + str
	}

	result := ""
	for i := 0; i < len(str); i += 2 {
		result += str[i:i+2] + " "
	}
	return result
}

func (c *Certificate) Equal(other *Certificate) bool {
	return c.cert.Equal(other.cert)
}
