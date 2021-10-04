package internal

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func GetCertificate(u *url.URL) (*Certificate, error) {
	switch {
	case u.Scheme == "file" || (u.Hostname() == "" && u.Path != ""):
		return getCertFromFile(u.Path)
	case u.Scheme == "http" || u.Scheme == "https":
		return getCertFromHTTP(u)
	case u.Scheme == "": // default to tcp
		u.Scheme = "tcp"
		fallthrough
	case u.Scheme == "tcp" || u.Scheme == "udp":
		if u.Hostname() == "" {
			return nil, fmt.Errorf("hostname is not specified")
		}
		if u.Port() == "" {
			return nil, fmt.Errorf("port is not specified")
		}
		return getCertFromTLS(u)
	default:
		return nil, fmt.Errorf("unsupported scheme %q", u.Scheme)
	}
}

func getCertFromFile(path string) (*Certificate, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	return parseCert(content, strings.TrimLeft(filepath.Ext(path), "."))
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
	cert := NewCertificate(certs[0])
	cert.hostname = u.Hostname()

	for _, c := range certs[1:] {
		cert.AddCertificateToChain(NewCertificate(c))
	}

	return cert, nil
}

func getCertFromHTTP(u *url.URL) (*Certificate, error) {
	resp, err := http.Get(u.String())
	if err != nil {
		return nil, err
	}

	if resp.StatusCode == 200 {
		buf := bytes.NewBuffer([]byte{})
		buf.ReadFrom(resp.Body)

		return parseCert(buf.Bytes(), strings.TrimLeft(filepath.Ext(u.Path), "."))
	}

	return nil, fmt.Errorf("cannot get certificate")
}
