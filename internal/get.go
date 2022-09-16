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

// GetCertificate returns a certificate from a given URL.
// Certificate can be sourced from a file (e.g. `file:///path/to/the/cert.pem`),
// a TCP/UDP connection (e.g. `tcp://1.2.3.4:443`, `https://google.com`)
// or downloaded (e.g. `https://letsencrypt.org/certs/isrgrootx1.pem`).
// If no scheme is provided, it defaults to TCP.
func GetCertificate(u *url.URL) (*Certificate, error) {
	switch {
	case u.Scheme == "file" || (u.Hostname() == "" && u.Path != ""):
		return getCertFromFile(u.Path)
	case u.Scheme == "http" || u.Scheme == "https":
		if strings.TrimLeft(u.Path, "/") != "" {
			return getCertFromHTTP(u)
		}

		if u.Port() == "" {
			u.Host = fmt.Sprintf("%s:%s", u.Hostname(), "443")
		}

		fallthrough
	case u.Scheme == "":
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
	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}}

	resp, err := client.Get(u.String())
	if err != nil {
		return nil, fmt.Errorf("failed to get certificate from %q: %v", u.String(), err)
	}

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("failed to get certificate from %q: got status code %d", u.String(), resp.StatusCode)
	}

	buf := bytes.NewBuffer([]byte{})
	buf.ReadFrom(resp.Body)

	return parseCert(buf.Bytes(), strings.TrimLeft(filepath.Ext(u.Path), "."))

}
