package cert

import (
	"crypto/tls"
	"crypto/x509"
	"math/big"
	"net"
	"net/url"
	"strings"
	"time"
)

// Get returns certificates sent by server under given URL.
func Get(u *url.URL) ([]*x509.Certificate, error) {
	netConn, err := net.DialTimeout(u.Scheme, u.Host, 5*time.Second)
	if err != nil {
		return nil, err
	}
	defer netConn.Close()

	cfg := &tls.Config{
		ServerName:         u.Hostname(),
		InsecureSkipVerify: true,
	}
	tlsConn := tls.Client(netConn, cfg)
	defer tlsConn.Close()

	if err := tlsConn.Handshake(); err != nil {
		return nil, err
	}

	return tlsConn.ConnectionState().PeerCertificates, nil
}

// IntermediatesCertPool create a pool with intermediate certificates.
func IntermediatesCertPool(certs []*x509.Certificate) *x509.CertPool {
	pool := x509.NewCertPool()
	for _, c := range certs {
		pool.AddCert(c)
	}
	return pool
}

// SerialNumber formats certificate's serial number.
func SerialNumber(sn *big.Int) string {
	str := strings.ToUpper(sn.Text(16))
	if len(str)%2 == 1 {
		str = "0" + str
	}

	result := ""
	for i := 0; i < len(str); i += 2 {
		result += str[i:i+2] + " "
	}
	return result
}
