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

	"github.com/krzysdabro/tlscert/internal/print"
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

	for i, cert := range certs {
		if i > 0 {
			print.Separator()
		}

		opts := x509.VerifyOptions{
			Intermediates: x509.NewCertPool(),
		}
		if !cert.IsCA {
			opts.DNSName = u.Hostname()
			for j, c := range certs {
				if j > i {
					opts.Intermediates.AddCert(c)
				}
			}
		}

		printCert(cert, opts)
	}
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

func printCert(cert *x509.Certificate, verifyOpts x509.VerifyOptions) {
	isValid := "yes"
	if _, err := cert.Verify(verifyOpts); err != nil {
		isValid = fmt.Sprintf("no (%s)", err)
	}

	serialNumber := strings.ToUpper(cert.SerialNumber.Text(16))

	print.PkixName("Subject", cert.Subject)
	print.PkixName("Issuer", cert.Issuer)
	if len(cert.DNSNames) > 0 {
		print.List("DNS Name", cert.DNSNames)
	}
	print.Field("Valid", isValid)
	print.Field("Not Valid Before", cert.NotBefore.Local().String())
	print.Field("Not Valid After", cert.NotAfter.Local().String())
	print.Field("Serial Number", serialNumber)
}
