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
	table.AddRow("Not Valid Before", cert.NotBefore().Local().String())
	table.AddRow("Not Valid After", cert.NotAfter().Local().String())

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

var (
	redBadge   = color.New(color.BgLightRed, color.FgWhite)
	greenBadge = color.New(color.BgLightGreen, color.FgBlack)
)

func certStatus(cert *Certificate) string {
	revoked := false
	if cert.IsOCSPPresent() {
		ok, err := cert.OCSPStatus()
		revoked = err == nil && !ok
	}

	switch {
	case revoked:
		return redBadge.Sprint("  REVOKED  ")
	case !cert.IsValid():
		return redBadge.Sprint(" NOT VALID ")
	default:
		return greenBadge.Sprint("   VALID   ")
	}
}
