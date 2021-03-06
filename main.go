package main

import (
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/krzysdabro/tlscert/internal"
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

	arg := pflag.Arg(0)

	// if URL does not contain scheme append slashes to prevent hostname from becoming the scheme
	if !strings.Contains(arg, "//") {
		arg = "//" + arg
	}

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

	internal.Print(cert)
	if chain := cert.Chain(); *fChain && len(chain) > 0 {
		for _, chainCert := range chain {
			fmt.Print("\n\n")
			internal.Print(chainCert)
		}
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, "Usage: %s [options] <url>\nOptions:\n", os.Args[0])
	pflag.PrintDefaults()
}
