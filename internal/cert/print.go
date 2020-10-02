package cert

import (
	"crypto/x509"

	"github.com/krzysdabro/tlscert/internal/print"
)

func Print(cert *x509.Certificate, verifyOpts x509.VerifyOptions) {
	v := certValidity{}
	_, v.err = cert.Verify(verifyOpts)

	printSingle(cert, v)
}

func PrintChain(cert *x509.Certificate, verifyOpts x509.VerifyOptions) {
	v := certValidity{}
	chains := [][]*x509.Certificate{}
	chains, v.err = cert.Verify(verifyOpts)

	if len(chains) == 0 {
		printSingle(cert, v)
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

func printSingle(cert *x509.Certificate, validity certValidity) {
	print.PkixName("Subject", cert.Subject)
	print.PkixName("Issuer", cert.Issuer)
	if len(cert.DNSNames) > 0 {
		print.List("DNS Name", cert.DNSNames)
	}
	print.Field("Valid", validity.String())
	print.Field("Not Valid Before", cert.NotBefore.Local().String())
	print.Field("Not Valid After", cert.NotAfter.Local().String())
	print.Field("Serial Number", SerialNumber(cert.SerialNumber))
}
