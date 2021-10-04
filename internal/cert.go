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
	chain    []*Certificate
	hostname string
}

func newCert(cert *x509.Certificate, chain []*x509.Certificate) *Certificate {
	c := &Certificate{
		cert:  cert,
		chain: []*Certificate{},
	}

	if len(chain) == 0 && len(cert.IssuingCertificateURL) > 0 {
		if u, err := url.Parse(cert.IssuingCertificateURL[0]); err == nil {
			if issuingCert, err := getCertFromHTTP(u); err == nil {
				c.chain = append(c.chain, issuingCert)
			}
		}
	}

	for i, chainCert := range chain {
		c.chain = append(c.chain, newCert(chainCert, chain[i+1:]))
	}

	return c
}

func (c *Certificate) chainCertPool() *x509.CertPool {
	pool := x509.NewCertPool()
	for _, chainCert := range c.chain {
		pool.AddCert(chainCert.cert)
	}
	return pool
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
	if len(c.cert.OCSPServer) == 0 || len(c.chain) == 0 {
		return false
	}

	body, err := ocsp.CreateRequest(c.cert, c.chain[0].cert, nil)
	if err != nil {
		return false
	}

	resp, err := http.Post(c.cert.OCSPServer[0], "application/ocsp-request", bytes.NewReader(body))
	if err != nil || resp.StatusCode != 200 {
		return false
	}

	buf := bytes.NewBuffer([]byte{})
	buf.ReadFrom(resp.Body)

	r, err := ocsp.ParseResponse(buf.Bytes(), c.chain[0].cert)
	return err == nil && r.Status == 1
}

func (c *Certificate) Chain() []*Certificate {
	return c.chain
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
