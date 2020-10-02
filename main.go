package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"net"
	"net/url"
	"os"
	"time"

	"github.com/krzysdabro/tlscert/internal/cert"
)

func main() {
	flag.Parse()
	if flag.NArg() == 0 {
		fmt.Fprintln(os.Stderr, "No URL was given")
		os.Exit(1)
	}

	u, err := parseURL(flag.Arg(0))
	if err != nil {
		fmt.Fprintln(os.Stderr, "Failed to parse given URL:", err)
		os.Exit(1)
	}

	certs, err := getCerts(u)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Failed to get certificates:", err)
		os.Exit(1)
	}

	opts := x509.VerifyOptions{
		Intermediates: cert.IntermediatesCertPool(certs[1:]),
		DNSName:       u.Hostname(),
	}
	cert.PrintChain(certs[0], opts)
}

func parseURL(arg string) (*url.URL, error) {
	u, err := url.Parse(arg)
	if err != nil {
		return nil, err
	}

	if u.Scheme == "https" {
		u.Scheme = "tcp"
		if u.Port() == "" {
			u.Host += ":443"
		}
	}

	return u, nil
}

func getCerts(u *url.URL) ([]*x509.Certificate, error) {
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

	err = tlsConn.Handshake()
	if err != nil {
		return nil, err
	}

	certs := tlsConn.ConnectionState().PeerCertificates
	return certs, nil
}
