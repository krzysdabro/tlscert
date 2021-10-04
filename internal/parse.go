package internal

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"go.mozilla.org/pkcs7"
)

func parseCert(data []byte, format string) (*Certificate, error) {
	switch format {
	case "pem":
		certs := []*x509.Certificate{}
		block, rest := pem.Decode(data)
		for block != nil {
			if block.Type == "CERTIFICATE" {
				c, err := x509.ParseCertificate(data)
				if err != nil {
					return nil, err
				}

				certs = append(certs, c)
			}
			block, rest = pem.Decode(rest)
		}

		return newCert(certs[0], certs[1:]), nil

	case "der":
		c, err := x509.ParseCertificate(data)
		if err != nil {
			return nil, err
		}

		return newCert(c, []*x509.Certificate{}), nil

	case "p7c":
		p7, err := pkcs7.Parse(data)
		if err != nil {
			return nil, err
		}

		return newCert(p7.Certificates[0], p7.Certificates[1:]), nil

	case "cer", "crt":
		c, err := parseCert(data, "der")
		if err != nil {
			c, err = parseCert(data, "pem")
			if err != nil {
				return nil, err
			}
		}

		return c, nil

	default:
		return nil, fmt.Errorf("unknown format %q", format)
	}
}
