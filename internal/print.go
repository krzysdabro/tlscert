package internal

import (
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/gookit/color"
	"github.com/gosuri/uitable"
	"github.com/krzysdabro/tlscert/internal/certutil"
)

var (
	tableSeparator = color.FgDarkGray.Sprint(" | ")

	redBadge   = color.New(color.BgLightRed, color.FgWhite)
	greenBadge = color.New(color.BgLightGreen, color.FgBlack)
)

type PrintOptions struct {
	SCTs bool
}

func Print(cert *Certificate, opts *PrintOptions) {
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

	table.AddRow("Serial Number", formatBigInt(cert.SerialNumber()))

	if sctList := cert.SignedCertificateTimestamps(); opts.SCTs && len(sctList) > 0 {
		for i, sct := range sctList {
			logOperator := "Unknown"
			if log := certutil.GetSCTLog(sct); log != nil {
				logOperator = log.Description
			}

			logKeyID := big.NewInt(0)
			logKeyID.SetBytes(sct.LogID.KeyID[:])

			encodedSignature := big.NewInt(0)
			encodedSignature.SetBytes(sct.Signature.Signature)

			table.AddRow(
				fmt.Sprintf("SCT #%d", i+1),
				fmt.Sprintf(
					"Version: %s\nLog Operator and Key ID:\n%s\n%s\nTimestamp: %s\nSignature Algorithm: %s\nSignature:\n%s",
					sct.SCTVersion.String(),
					indentText(logOperator, 1),
					indentText(formatBigInt(logKeyID), 1),
					time.Unix(int64(sct.Timestamp/1000), 0).Local().String(),
					sct.Signature.Algorithm.Signature.String(),
					indentText(formatBigInt(encodedSignature), 1),
				),
			)
		}
	}

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

func indentText(text string, level int) string {
	indent := strings.Repeat("  ", level)
	return fmt.Sprintf("%s%s", indent, strings.ReplaceAll(text, "\n", fmt.Sprintf("\n%s", indent)))
}

func formatBigInt(i *big.Int) string {
	str := strings.ToUpper(i.Text(16))
	if len(str)%2 == 1 {
		str = "0" + str
	}

	result := ""
	for i := 0; i < len(str); i += 2 {
		result += str[i : i+2]
		if (i+2)%32 == 0 {
			result += "\n"
		} else {
			result += " "
		}
	}

	return strings.TrimSuffix(result, "\n")
}

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
