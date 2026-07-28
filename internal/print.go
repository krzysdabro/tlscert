package internal

import (
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/gosuri/uitable"
	"github.com/krzysdabro/tlscert/internal/certutil"
)

var (
	tableSeparator = color.New(color.FgHiBlack).Sprint(" │ ")

	redBadge   = color.New(color.BgHiRed, color.FgWhite)
	greenBadge = color.New(color.BgHiGreen, color.FgBlack)
)

// PrintOptions defines cetificate printing options.
type PrintOptions struct {
	SCTs bool
}

// Print prints details about certificate.
func (c *Certificate) Print(opts *PrintOptions) {
	fmt.Printf("%s %s\n", certStatus(c), c.CommonName())

	table := uitable.New()
	table.Wrap = true
	table.Separator = tableSeparator

	table.AddRow("Subject", printPkixName(c.Subject()))
	table.AddRow("Issuer", printPkixName(c.Issuer()))
	table.AddRow("Signature Algorithm", c.SignatureAlgorithm())
	if v := c.KeyUsage(); v != "" {
		table.AddRow("Key Usage", v)
	}
	if v := c.ExtKeyUsage(); v != "" {
		table.AddRow("Extended Key Usage", v)
	}
	if v := c.CertificatePolicies(); v != "" {
		table.AddRow("Certificate Policies", v)
	}
	if v := c.QCStatement(); len(v) > 0 {
		table.AddRow("QC Statement", v)
	}
	table.AddRow("Not Valid Before", c.NotBefore().Local().String())
	table.AddRow("Not Valid After", c.NotAfter().Local().String())

	if certDNS := c.DNSNames(); len(certDNS) > 0 {
		table.AddRow("DNS Names", strings.Join(certDNS, "\n"))
	}

	if certIPs := c.IPAddresses(); len(certIPs) > 0 {
		ips := make([]string, len(certIPs))
		for i, ip := range certIPs {
			ips[i] = ip.String()
		}
		table.AddRow("IP Addresses", ips)
	}

	table.AddRow("Serial Number", formatBigInt(c.SerialNumber()))

	if sctList := c.SignedCertificateTimestamps(); opts.SCTs && len(sctList) > 0 {
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

// modified version of
// https://github.com/golang/go/blob/6db72bb92b2ab681ae177589b70b573e6e337b96/src/crypto/x509/pkix/pkix.go#L27-L36
var attributeTypeNames = map[string]string{
	"2.5.4.6":                  "C",
	"2.5.4.10":                 "O",
	"2.5.4.11":                 "OU",
	"2.5.4.3":                  "CN",
	"2.5.4.5":                  "SERIALNUMBER",
	"2.5.4.7":                  "L",
	"2.5.4.8":                  "ST",
	"2.5.4.9":                  "STREET",
	"2.5.4.15":                 "businessCategory",
	"2.5.4.17":                 "POSTALCODE",
	"2.5.4.97":                 "organizationIdentifier",
	"1.3.6.1.4.1.311.60.2.1.1": "jurisdictionOfIncorporationLocalityName",
	"1.3.6.1.4.1.311.60.2.1.2": "jurisdictionOfIncorporationStateOrProvinceName",
	"1.3.6.1.4.1.311.60.2.1.3": "jurisdictionOfIncorporationCountryName",
}

func printPkixName(name pkix.Name) string {
	b := strings.Builder{}

	for i, v := range name.Names {
		if i > 0 {
			b.WriteString("\n")
		}

		t := v.Type.String()
		if attrName, ok := attributeTypeNames[t]; ok {
			b.WriteString(attrName)
		} else {
			b.WriteString(t)
		}

		b.WriteByte('=')
		b.WriteString(v.Value.(string))
	}
	return b.String()
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

	lBorder, rBorder := " ", " "

	// add border when output is not a terminal
	if color.NoColor {
		lBorder, rBorder = "[", "]"
	}

	switch {
	case revoked:
		return redBadge.Sprintf("%s REVOKED %s", lBorder, rBorder)
	case !cert.IsValid():
		return redBadge.Sprintf("%sNOT VALID%s", lBorder, rBorder)
	default:
		return greenBadge.Sprintf("%s  VALID  %s", lBorder, rBorder)
	}
}

func init() {
	// use simple pipe as separator when output is not a terminal
	if color.NoColor {
		tableSeparator = " | "
	}
}
