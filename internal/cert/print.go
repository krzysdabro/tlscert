package cert

import (
	"crypto/x509"
	"fmt"

	"github.com/krzysdabro/tlscert/internal/print"
)

// Print prints out single certificate.
func Print(cert *x509.Certificate, verifyOpts x509.VerifyOptions) {
	_, err := cert.Verify(verifyOpts)

	printSingle(cert, err)
}

// PrintChain prints out all certificates in chain.
func PrintChain(cert *x509.Certificate, verifyOpts x509.VerifyOptions) {
	chains, err := cert.Verify(verifyOpts)

	if len(chains) == 0 {
		printSingle(cert, err)
		return
	}

	for i, c := range chains[0] {
		if i > 0 {
			print.Separator()
		}
		opts := x509.VerifyOptions{
			Intermediates: IntermediatesCertPool(chains[0][i+1:]),
		}
		Print(c, opts)
	}
}

func printSingle(cert *x509.Certificate, validityErr error) {
	print.PkixName("Subject", cert.Subject)
	print.PkixName("Issuer", cert.Issuer)
	if len(cert.DNSNames) > 0 {
		print.List("DNS Name", cert.DNSNames)
	}
	print.Field("Valid", isValid(validityErr))
	print.Field("Not Valid Before", cert.NotBefore.Local().String())
	print.Field("Not Valid After", cert.NotAfter.Local().String())
	print.Field("Serial Number", SerialNumber(cert.SerialNumber))
}

func isValid(err error) string {
	if err == nil {
		return "yes"
	}
	return fmt.Sprintf("no (%s)", err.Error())
}
