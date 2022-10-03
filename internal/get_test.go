package internal_test

import (
	"crypto/x509"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/krzysdabro/tlscert/internal"
)

func TestGetCertificate(t *testing.T) {
	fs := os.DirFS("testdata")

	abs, _ := filepath.Abs("testdata/cert.cer")
	validCert := loadCert(t, fs, "cert.pem")

	startHTTPSServer(t, &serverOptions{":8443", fs, "testdata/cert.pem", "testdata/cert.key"})

	cases := []struct {
		url  string
		cert *x509.Certificate

		err                error
		ignoreErrorContent bool
	}{
		{url: "testdata/foo.pem", ignoreErrorContent: true},
		{url: "testdata/cert.cer", cert: validCert},
		{url: "./testdata/cert.cer", cert: validCert},
		{url: "../internal/testdata/cert.cer", cert: validCert},
		{url: abs, cert: validCert},
		{url: "file://testdata/cert.cer", ignoreErrorContent: true},
		{url: "file://./testdata/cert.cer", ignoreErrorContent: true},
		{url: "file://../internal/testdata/cert.cer", ignoreErrorContent: true},
		{url: fmt.Sprintf("file://%s", abs), cert: validCert},
		{url: "https://127.0.0.1:8443", cert: validCert},
		{url: "https://127.0.0.1:8443/cert.pem", cert: validCert},
		{url: "https://127.0.0.1:8443/foo.pem", err: fmt.Errorf(`failed to get certificate from "https://127.0.0.1:8443/foo.pem": got status code 404`)},
		{url: "tcp://127.0.0.1:8443", cert: validCert},
		{url: "tcp://:1234", err: fmt.Errorf("hostname is not specified")},
		{url: "tcp://127.0.0.1", err: fmt.Errorf("port is not specified")},
		{url: "foo://127.0.0.1:8443", err: fmt.Errorf(`unsupported scheme "foo"`)},
		{url: "http://0.0.0.0", err: fmt.Errorf("dial tcp 0.0.0.0:443: connect: connection refused")},
		{url: "http://foo.bar/cert.pem", err: fmt.Errorf(`failed to get certificate from "http://foo.bar/cert.pem": Get "http://foo.bar/cert.pem": dial tcp: lookup foo.bar: no such host`)},
	}

	for _, c := range cases {
		t.Run(c.url, func(t *testing.T) {
			u, err := url.Parse(c.url)
			if err != nil {
				t.Fatalf("cannot parse URL: %s", err)
			}

			cert, err := internal.GetCertificate(u)
			if c.cert == nil && err == nil {
				t.Fatal("expected error, got nil")
			}

			var retErr error
			if err != nil {
				retErr = fmt.Errorf(err.Error())
			}

			if diff := cmp.Diff(c.err, retErr, equateErrorMessage); !c.ignoreErrorContent && diff != "" {
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

func TestGetCertificate_Chains(t *testing.T) {
	fs := os.DirFS("testdata")

	want := internal.NewCertificate(loadCert(t, fs, "cert.pem"))
	chain1 := internal.NewCertificate(loadCert(t, fs, "lets-encrypt-r3.pem"))
	chain2 := internal.NewCertificate(loadCert(t, fs, "isrgrootx1.pem"))

	want.AddCertificateToChain(chain1)
	want.AddCertificateToChain(chain2)

	startHTTPSServer(t, &serverOptions{":8443", fs, "testdata/full.pem", "testdata/cert.key"})

	u, err := url.Parse("https://127.0.0.1:8443")
	if err != nil {
		t.Fatalf("cannot parse URL: %s", err)
	}

	cert, err := internal.GetCertificate(u)

	if diff := cmp.Diff(nil, err, equateErrorMessage); diff != "" {
		t.Fatalf("mismatch (-want +got):\n%s", diff)
	}

	if diff := cmp.Diff(cert, want); diff != "" {
		t.Fatalf("mismatch (-want +got):\n%s", diff)
	}

	if diff := cmp.Diff(cert.Chain(), want.Chain()); diff != "" {
		t.Fatalf("mismatch (-want +got):\n%s", diff)
	}
}
