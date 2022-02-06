package certutil

import (
	"bytes"
	"crypto/x509"
	"fmt"
	"net/http"
)

// CheckCRL scans Certificate Revocation List and reports whether the certificate is revoked.
func CheckCRL(cert *x509.Certificate) (bool, error) {
	if len(cert.CRLDistributionPoints) == 0 {
		return false, fmt.Errorf("")
	}

	resp, err := http.Get(cert.CRLDistributionPoints[0])
	if err != nil {
		return false, fmt.Errorf("")
	}

	if resp.StatusCode != 200 {
		return false, fmt.Errorf("")
	}

	buf := bytes.NewBuffer([]byte{})
	buf.ReadFrom(resp.Body)

	crl, err := x509.ParseCRL(buf.Bytes())
	if err != nil {
		return false, fmt.Errorf("")
	}

	if err := cert.CheckCRLSignature(crl); err != nil {
		return false, err
	}

	return true, nil
}
