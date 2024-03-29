package internal

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"go.mozilla.org/pkcs7"
	"golang.org/x/crypto/pkcs12"
)

func ParseCertificate(data []byte, format string) (*Certificate, error) {
	switch format {
	case "pem":
		return parsePEM(data)

	case "der":
		c, err := x509.ParseCertificate(data)
		if err != nil {
			return nil, fmt.Errorf("failed to parse DER: %v", err)
		}

		return NewCertificate(c), nil

	case "p7c":
		p7, err := pkcs7.Parse(data)
		if err != nil {
			return nil, fmt.Errorf("failed to parse P7C: %v", err)
		}

		cert := NewCertificate(p7.Certificates[0])
		for _, c := range p7.Certificates[1:] {
			cert.AddCertificateToChain(NewCertificate(c))
		}

		return cert, nil

	case "pfx":
		_, crt, err := pkcs12.Decode(data, "")
		if err != nil {
			return nil, fmt.Errorf("failed to parse PKCS#12: %v", err)
		}

		return NewCertificate(crt), nil

	case "", "cer", "crt":
		c, err := ParseCertificate(data, "der")
		if err != nil {
			c, err = ParseCertificate(data, "pem")
			if err != nil {
				return nil, fmt.Errorf("data is neither DER or PEM")
			}
		}

		return c, nil

	default:
		return nil, fmt.Errorf("unknown format %q", format)
	}
}

func parsePEM(data []byte) (*Certificate, error) {
	var cert *Certificate
	block, rest := pem.Decode(data)
	for block != nil {
		if block.Type == "CERTIFICATE" {
			c, err := ParseCertificate(block.Bytes, "der")
			if err != nil {
				return nil, fmt.Errorf("failed to parse PEM: %v", err)
			}

			if cert == nil {
				cert = c
			} else {
				cert.AddCertificateToChain(c)
			}
		}
		block, rest = pem.Decode(rest)
	}

	if cert == nil {
		return nil, fmt.Errorf("failed to parse PEM: no CERTIFICATE block found")
	}

	return cert, nil
}
