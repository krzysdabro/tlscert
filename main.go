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
)

var separator = strings.Repeat("-", 30)

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
			fmt.Println(separator)
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
	valid := "yes"
	if _, err := cert.Verify(verifyOpts); err != nil {
		valid = fmt.Sprintf("no (%s)", err)
	}

	serialNumber := strings.ToUpper(cert.SerialNumber.Text(16))

	print("Subject", cert.Subject)
	print("Issuer", cert.Issuer)
	if len(cert.DNSNames) > 0 {
		print("DNS names", strings.Join(cert.DNSNames, ", "))
	}
	print("Valid", valid)
	print("Not valid before", cert.NotBefore)
	print("Not valid after", cert.NotAfter)
	print("Serial number", serialNumber)
}

func print(title string, value interface{}) {
	fmt.Printf("%-20s  %s\n", title, value)
}
