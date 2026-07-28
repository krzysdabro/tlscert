package internal

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"strings"
	"time"

	ct "github.com/google/certificate-transparency-go"
	"github.com/krzysdabro/tlscert/internal/certutil"
)

var (
	wildcardPolicy = "2.5.29.32.0"
	knownPolicies  = map[string]string{
		"2.23.140.1.1":     "Extended Validation",
		"2.23.140.1.2.1":   "Domain Validated",
		"2.23.140.1.2.2":   "Organizational Validation",
		"2.23.140.1.2.3":   "Individual Validation",
		"2.23.140.1.3":     "EV Code Signing Certificate",
		"2.23.140.1.4.1":   "Code Signing Certificate",
		"2.23.140.1.4.2":   "Timestamp Certificate",
		"0.4.0.194112.1.0": "ETSI QCP-n",
		"0.4.0.194112.1.1": "ETSI QCP-l",
		"0.4.0.194112.1.2": "ETSI QCP-n-qscd",
		"0.4.0.194112.1.3": "ETSI QCP-l-qscd",
		"0.4.0.194112.1.4": "ETSI QEVCP-w",
		"0.4.0.194112.1.5": "ETSI QNCP-w",
		"0.4.0.194112.1.6": "ETSI QNCP-w-gen",
	}
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

// SignatureAlgorithm returns signature algorithm name used in the certificate.
func (c *Certificate) SignatureAlgorithm() string {
	return c.cert.SignatureAlgorithm.String()
}

// KeyUsage returns a set of valid usages for the key.
func (c *Certificate) KeyUsage() string {
	ku := c.cert.KeyUsage
	result := []string{}

	for i := 1; i <= 256; i = i << 1 {
		if v := int(ku) & i; v != 0 {
			result = append(result, x509.KeyUsage(v).String())
		}
	}

	return strings.Join(result, "\n")
}

// ExtKeyUsage returns a set of extended usages for the key.
func (c *Certificate) ExtKeyUsage() string {
	result := []string{}

	for _, ku := range c.cert.ExtKeyUsage {
		result = append(result, ku.String())
	}

	return strings.Join(result, "\n")
}

// CertificatePolicies returns policies applied to the certificate, with known
// OIDs replaced by their names and the anyPolicy OID omitted.
func (c *Certificate) CertificatePolicies() string {
	result := []string{}

	for _, oid := range c.cert.Policies {
		s := oid.String()
		if s == wildcardPolicy {
			continue
		}

		if name, ok := knownPolicies[s]; ok {
			result = append(result, name)
			continue
		}

		result = append(result, s)
	}

	return strings.Join(result, "\n")
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

func (c *Certificate) QCStatement() string {
	for _, e := range c.cert.Extensions {
		if !e.Id.Equal(certutil.OIDQCStatementsExt) {
			continue
		}

		statements, err := certutil.ParseQCStatement(e.Value)
		if err != nil {
			return err.Error()
		}

		b := strings.Builder{}
		for i, s := range statements {
			if i > 0 {
				b.WriteString("\n")
			}
			b.WriteString(s.String())
		}
		return b.String()
	}
	return ""
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
