package main

import (
	"fmt"
	"net/url"
	"os"

	"github.com/krzysdabro/tlscert/internal"
	"github.com/spf13/pflag"
)

var (
	fNoChain = pflag.Bool("no-chain", false, "Do not show the chain of trust")
	fNoAIA   = pflag.Bool("no-aia", false, "Do not follow AIA extension")
	fNoSCT   = pflag.Bool("no-sct", false, "Do not print Signed Certificate Timestamps")
)

func main() {
	pflag.Usage = usage
	pflag.Parse()

	if pflag.NArg() != 1 {
		pflag.Usage()
		os.Exit(1)
	}

	arg := pflag.Arg(0)

	u, err := url.Parse(arg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Failed to parse URL:", err)
		os.Exit(1)
	}

	cert, err := internal.GetCertificate(u)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Failed to get certificates:", err)
		os.Exit(1)
	}

	if !*fNoAIA {
		cert.DownloadIssuingCertificate()
	}

	opts := &internal.PrintOptions{
		SCTs: !*fNoSCT,
	}

	cert.Print(opts)
	if chain := cert.Chain(); !*fNoChain && len(chain) > 0 {
		for _, chainCert := range chain {
			fmt.Print("\n\n")
			chainCert.Print(opts)
		}
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, "Usage: %s [options] <url>\nOptions:\n", os.Args[0])
	pflag.PrintDefaults()
}
