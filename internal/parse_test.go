package internal_test

import (
	"crypto/x509"
	"fmt"
	"os"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/krzysdabro/tlscert/internal"
)

var invalidPEM1 = []byte(`
-----BEGIN CERTIFICATE-----
Z2FyYmFnZSBnYXJiYWdlIGdhcmJhZ2UgZ2FyYmFnZQpnYXJiYWdlIGdhcmJhZ2Ug
Z2FyYmFnZSBnYXJiYWdlCmdhcmJhZ2UgZ2FyYmFnZSBnYXJiYWdlIGdhcmJhZ2UK
Z2FyYmFnZSBnYXJiYWdlIGdhcmJhZ2UgZ2FyYmFnZQpnYXJiYWdlIGdhcmJhZ2Ug
Z2FyYmFnZSBnYXJiYWdlCmdhcmJhZ2UgZ2FyYmFnZSBnYXJiYWdlIGdhcmJhZ2UK
Z2FyYmFnZSBnYXJiYWdlIGdhcmJhZ2UgZ2FyYmFnZQ==
-----END CERTIFICATE-----`)

var invalidPEM2 = []byte(`
-----BEGIN PRIVATE KEY-----
MIIJQQIBADANBgkqhkiG9w0BAQEFAASCCSswggknAgEAAoICAQCqjyZ6Q0HwSy0t
ug96872E1eVyobyXdf1m7GLimVofigon7urVMbraMJt7ckSptfPNKLVPe34/8Ne7
-----END PRIVATE KEY-----`)

func TestParseCertificate(t *testing.T) {
	fs := os.DirFS("testdata")
	rawDERCert := loadRawCert(t, fs, "cert.cer")
	rawPEMCert := loadRawCert(t, fs, "cert.pem")
	rawP7CCert := loadRawCert(t, fs, "cert.p7c")
	rawPKCS12Cert := loadRawCert(t, fs, "cert.pfx")
	DERCert := loadCert(t, fs, "cert.cer")
	PEMCert := loadCert(t, fs, "cert.pem")
	P7CCert := loadCert(t, fs, "cert.pem")

	cases := []struct {
		name   string
		data   []byte
		format string
		cert   *x509.Certificate
		err    error
	}{
		{name: "valid .cer certificate", data: rawDERCert, format: "cer", cert: DERCert},
		{name: "valid .pem certificate", data: rawPEMCert, format: "pem", cert: PEMCert},
		{name: "valid .p7c certificate", data: rawP7CCert, format: "p7c", cert: P7CCert},
		{name: "valid .pfx certificate", data: rawPKCS12Cert, format: "pfx", cert: P7CCert},
		{name: "garbage data in PEM", data: invalidPEM1, format: "pem", err: fmt.Errorf("failed to parse PEM: failed to parse DER: x509: malformed certificate")},
		{name: "no CERTIFICATE block", data: invalidPEM2, format: "pem", err: fmt.Errorf("failed to parse PEM: no CERTIFICATE block found")},
		{name: "invalid DER", data: invalidPEM1, format: "der", err: fmt.Errorf("failed to parse DER: x509: malformed certificate")},
		{name: "garbage data", data: []byte("garbage"), format: "", err: fmt.Errorf("data is neither DER or PEM")},
		{name: "unknown format", data: rawDERCert, format: "foo", err: fmt.Errorf(`unknown format "foo"`)},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cert, err := internal.ParseCertificate(c.data, c.format)

			if c.cert == nil && c.err == nil && err == nil {
				t.Fatal("expected error, got nil")
			}

			if diff := cmp.Diff(err, c.err, equateErrorMessage); diff != "" {
				t.Fatalf("mismatch (-want +got):\n%s", diff)
			}

			if c.cert == nil {
				return
			}

			want := internal.NewCertificate(c.cert)
			if diff := cmp.Diff(cert, want); diff != "" {
				t.Fatalf("mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
