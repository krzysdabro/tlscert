package internal

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"
)

func getCertFromFile(path string) (*Certificate, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	certs := []*x509.Certificate{}

	block, rest := pem.Decode(content)
	for block != nil {
		if block.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, err
			}
			certs = append(certs, cert)
		}
		block, rest = pem.Decode(rest)
	}

	return newCert(certs[0], certs[1:]), nil
}

func getCertFromTLS(u *url.URL) (*Certificate, error) {
	netConn, err := net.DialTimeout(u.Scheme, u.Host, 5*time.Second)
	if err != nil {
		return nil, err
	}
	defer netConn.Close()

	cfg := &tls.Config{
		ServerName:         u.Hostname(),
		InsecureSkipVerify: true,
	}
	tlsConn := tls.Client(netConn, cfg)
	defer tlsConn.Close()

	if err := tlsConn.Handshake(); err != nil {
		return nil, err
	}

	certs := tlsConn.ConnectionState().PeerCertificates
	cert := newCert(certs[0], certs[1:])
	cert.hostname = u.Hostname()
	return cert, nil
}

func getCertFromHTTP(u *url.URL) (*Certificate, error) {
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("scheme should be either http or https")
	}

	resp, _ := http.Get(u.String())
	if resp.StatusCode == 200 {
		buf := bytes.NewBuffer([]byte{})
		buf.ReadFrom(resp.Body)
		c, _ := x509.ParseCertificate(buf.Bytes())
		return &Certificate{cert: c}, nil
	}
	return nil, fmt.Errorf("x")
}
