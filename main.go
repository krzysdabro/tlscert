package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/krzysdabro/tlscert/internal/cert"
)

var (
	fShowChain = flag.Bool("show-chain", false, "show certificate chain")
)

func main() {
	flag.Usage = usage
	flag.Parse()

	if flag.NArg() != 1 {
		flag.Usage()
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
	if *fShowChain {
		cert.PrintChain(certs[0], opts)
	} else {
		cert.Print(certs[0], opts)
	}
}

func usage() {
	cl := flag.CommandLine
	fmt.Fprintf(cl.Output(), "Usage: %s [options] <url>\n", cl.Name())
	cl.PrintDefaults()
}

func parseURL(arg string) (*url.URL, error) {
	// if URL does not contain scheme append slashes to prevent hostname from becoming the scheme
	if !strings.Contains(arg, "//") {
		arg = "//" + arg
	}

	u, err := url.Parse(arg)
	if err != nil {
		return nil, err
	}

	switch u.Scheme {
	case "https":
		u.Scheme = "tcp"
		u.Host = net.JoinHostPort(u.Hostname(), "443")
	case "":
		u.Scheme = "tcp"
		fallthrough
	case "tcp", "udp":
		if u.Port() == "" {
			return nil, fmt.Errorf("port not specified")
		}
	default:
		return nil, fmt.Errorf("unsupported scheme %q", u.Scheme)
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

	if err := tlsConn.Handshake(); err != nil {
		return nil, err
	}

	return tlsConn.ConnectionState().PeerCertificates, nil
}
