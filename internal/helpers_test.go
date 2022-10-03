package internal_test

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"io/fs"
	"net/http"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
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

type serverOptions struct {
	addr string
	fs   fs.FS

	certFile string
	keyFile  string
}

func startHTTPSServer(t *testing.T, opts *serverOptions) {
	srv := http.Server{
		Addr:    opts.addr,
		Handler: http.FileServer(http.FS(opts.fs)),
	}

	t.Cleanup(func() {
		srv.Shutdown(context.Background())
	})

	go func() {
		if err := srv.ListenAndServeTLS(opts.certFile, opts.keyFile); err != http.ErrServerClosed {
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
