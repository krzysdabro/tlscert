package main

import (
	"fmt"
	"net/url"
	"os"

	"github.com/krzysdabro/tlscert/internal"
	"github.com/spf13/pflag"
)

var (
	fChain              = pflag.Bool("chain", false, "show certificate chain")
	fDisableAIAFetching = pflag.Bool("disable-aia-fetching", false, "disable fetching certificates provided by Authority Information Access extension")
	fSCT                = pflag.Bool("sct", false, "print Signed Certificate Timestamps")
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

	if !*fDisableAIAFetching {
		cert.DownloadIssuingCertificate()
	}

	opts := &internal.PrintOptions{
		SCTs: *fSCT,
	}

	cert.Print(opts)
	if chain := cert.Chain(); *fChain && len(chain) > 0 {
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
