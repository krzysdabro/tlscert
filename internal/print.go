package internal

import (
	"crypto/x509/pkix"
	"fmt"
	"strings"

	"github.com/gookit/color"
	"github.com/gosuri/uitable"
)

var tableSeparator = color.FgDarkGray.Sprint(" | ")

func Print(cert *Certificate) {
	fmt.Printf("%s %s\n", certStatus(cert), cert.CommonName())

	table := uitable.New()
	table.Wrap = true
	table.Separator = tableSeparator

	table.AddRow("Subject", printPkixName(cert.Subject()))
	table.AddRow("Issuer", printPkixName(cert.Issuer()))

	if certDNS := cert.DNSNames(); len(certDNS) > 0 {
		table.AddRow("DNS Names", strings.Join(certDNS, "\n"))
	}

	if certIPs := cert.IPAddresses(); len(certIPs) > 0 {
		ips := make([]string, len(certIPs))
		for i, ip := range certIPs {
			ips[i] = ip.String()
		}
		table.AddRow("IP Addresses", ips)
	}

	table.AddRow("Not Valid Before", cert.NotBefore().Local().String())
	table.AddRow("Not Valid After", cert.NotAfter().Local().String())
	table.AddRow("Serial Number", cert.SerialNumber())

	fmt.Println(table)
}

func printPkixName(name pkix.Name) string {
	s := name.String()
	for i := range s {
		if len(s) > i && s[i] == ',' {
			if s[i-1] != '\\' {
				s = s[:i] + "\n" + s[i+1:]
			} else {
				s = s[:i-1] + s[i:]
			}
		}
	}
	return s
}

func certStatus(cert *Certificate) string {
	switch {
	case !cert.IsValid():
		return color.BgLightRed.Sprint(" NOT VALID ")
	case cert.IsRevoked():
		return color.BgLightRed.Sprint("  REVOKED  ")
	default:
		return color.New(color.BgLightGreen, color.FgBlack).Sprint("   VALID   ")
	}
}
