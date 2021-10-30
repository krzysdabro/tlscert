package certutil

import (
	"bytes"
	"crypto/x509"
	"fmt"
	"net/http"

	"golang.org/x/crypto/ocsp"
)

func CheckOCSP(cert *x509.Certificate, issuer *x509.Certificate) (bool, error) {
	if len(cert.OCSPServer) == 0 {
		return false, fmt.Errorf("no OCSP server present for certificate")
	}

	body, err := ocsp.CreateRequest(cert, issuer, nil)
	if err != nil {
		return false, fmt.Errorf("OCSP request error")
	}

	resp, err := http.Post(cert.OCSPServer[0], "application/ocsp-request", bytes.NewReader(body))
	if err != nil || resp.StatusCode != 200 {
		return false, fmt.Errorf("OCSP request error")
	}

	buf := bytes.NewBuffer([]byte{})
	buf.ReadFrom(resp.Body)

	r, err := ocsp.ParseResponse(buf.Bytes(), issuer)
	if err != nil {
		return false, err
	}

	return r.Status == ocsp.Good, nil
}
