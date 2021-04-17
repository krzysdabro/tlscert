package main

import (
	"crypto/x509"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"

	"github.com/krzysdabro/tlscert/internal/cert"
	"github.com/spf13/pflag"
)

var (
	fChain = pflag.Bool("chain", false, "show certificate chain")
)

func main() {
	pflag.Usage = usage
	pflag.Parse()

	if pflag.NArg() != 1 {
		pflag.Usage()
		os.Exit(1)
	}

	u, err := parseURL(pflag.Arg(0))
	if err != nil {
		fmt.Fprintln(os.Stderr, "Failed to parse given URL:", err)
		os.Exit(1)
	}

	certs, err := cert.Get(u)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Failed to get certificates:", err)
		os.Exit(1)
	}

	opts := x509.VerifyOptions{
		Intermediates: cert.IntermediatesCertPool(certs[1:]),
		DNSName:       u.Hostname(),
	}
	if *fChain {
		cert.PrintChain(certs[0], opts)
	} else {
		cert.Print(certs[0], opts)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, "Usage: %s [options] <url>\n", os.Args[0])
	pflag.PrintDefaults()
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
