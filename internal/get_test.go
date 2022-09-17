package internal_test

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/krzysdabro/tlscert/internal"
)

func loadRawCert(t *testing.T, fs fs.FS, name string) []byte {
	t.Helper()

	f, err := fs.Open(name)
	if err != nil {
		t.Fatalf("cannot load certificate %s: %s", name, err)
	}

	buf := bytes.NewBuffer([]byte{})
	buf.ReadFrom(f)

	if err != nil {
		t.Fatalf("cannot load certificate %s: %s", name, err)
	}

	return buf.Bytes()
}

func loadCert(t *testing.T, fs fs.FS, name string) *x509.Certificate {
	t.Helper()

	bytes := loadRawCert(t, fs, name)
	if filepath.Ext(name) == ".pem" {
		block, _ := pem.Decode(bytes)
		bytes = block.Bytes
	}

	cert, err := x509.ParseCertificate(bytes)
	if err != nil {
		t.Fatalf("cannot load certificate %s: %s", name, err)
	}

	return cert
}

func startHTTPSServer(t *testing.T, fs fs.FS) {
	srv := http.Server{
		Addr:    ":8443",
		Handler: http.FileServer(http.FS(fs)),
	}

	t.Cleanup(func() {
		srv.Shutdown(context.Background())
	})

	go func() {
		if err := srv.ListenAndServeTLS("testdata/cert.pem", "testdata/cert.key"); err != http.ErrServerClosed {
			t.Logf("HTTPS Server: %s", err)
		}
	}()
}

var equateErrorMessage = cmp.Comparer(func(x, y error) bool {
	if x == nil || y == nil {
		return x == nil && y == nil
	}
	return x.Error() == y.Error()
})

func TestGetCertificate(t *testing.T) {
	fs := os.DirFS("testdata")

	abs, _ := filepath.Abs("testdata/cert.cer")
	CERCert := loadCert(t, fs, "cert.cer")
	PEMCert := loadCert(t, fs, "cert.pem")

	startHTTPSServer(t, fs)

	cases := []struct {
		url  string
		cert *x509.Certificate
		err  error
	}{
		{url: "testdata/foo.pem", cert: nil},
		{url: "testdata/cert.cer", cert: CERCert},
		{url: "./testdata/cert.cer", cert: CERCert},
		{url: "../internal/testdata/cert.cer", cert: CERCert},
		{url: abs, cert: CERCert},
		{url: "file://testdata/cert.cer", cert: nil},
		{url: "file://./testdata/cert.cer", cert: nil},
		{url: "file://../internal/testdata/cert.cer", cert: nil},
		{url: fmt.Sprintf("file://%s", abs), cert: CERCert},
		{url: "https://127.0.0.1:8443", cert: PEMCert},
		{url: "https://127.0.0.1:8443/cert.pem", cert: PEMCert},
		{url: "https://127.0.0.1:8443/foo.pem", cert: nil, err: fmt.Errorf(`failed to get certificate from "https://127.0.0.1:8443/foo.pem": got status code 404`)},
		{url: "tcp://127.0.0.1:8443", cert: PEMCert},
		{url: "tcp://:1234", cert: nil, err: fmt.Errorf("hostname is not specified")},
		{url: "tcp://127.0.0.1", cert: nil, err: fmt.Errorf("port is not specified")},
		{url: "foo://127.0.0.1:8443", cert: nil, err: fmt.Errorf(`unsupported scheme "foo"`)},
	}

	for _, c := range cases {
		t.Run(c.url, func(t *testing.T) {
			u, err := url.Parse(c.url)
			if err != nil {
				t.Fatalf("cannot parse URL: %s", err)
			}

			cert, err := internal.GetCertificate(u)
			if c.cert == nil && c.err == nil && err == nil {
				t.Fatal("expected error, got nil")
			}

			if diff := cmp.Diff(err, c.err, equateErrorMessage); c.err != nil && diff != "" {
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
