package certutil

import (
	"crypto/x509"
	"encoding/asn1"
	"net/http"

	ct "github.com/google/certificate-transparency-go"
	ctlogs "github.com/google/certificate-transparency-go/loglist"
	cttls "github.com/google/certificate-transparency-go/tls"
	ctx509 "github.com/google/certificate-transparency-go/x509"
	ctx509util "github.com/google/certificate-transparency-go/x509util"
)

var oidExtensionCT = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2}

var ctLogList *ctlogs.LogList

// GetSCTs returns Signed Certificate Timestamps from certificate.
func GetSCTs(cert *x509.Certificate) (result []ct.SignedCertificateTimestamp) {
	var serializedSCTs []byte

	for _, e := range cert.Extensions {
		if !e.Id.Equal(oidExtensionCT) {
			continue
		}
		if _, err := asn1.Unmarshal(e.Value, &serializedSCTs); err != nil {
			return
		}
	}

	var sctList ctx509.SignedCertificateTimestampList
	if rest, err := cttls.Unmarshal(serializedSCTs, &sctList); err != nil || len(rest) > 0 {
		return
	}

	for _, serializedSCT := range sctList.SCTList {
		var sct ct.SignedCertificateTimestamp
		if rest, err := cttls.Unmarshal(serializedSCT.Val, &sct); err != nil || len(rest) > 0 {
			return
		}
		result = append(result, sct)
	}

	return
}

// GetSCTLog return a SCT log relevant to given SCT.
func GetSCTLog(sct ct.SignedCertificateTimestamp) *ctlogs.Log {
	if ctLogList == nil {
		return nil
	}

	return ctLogList.FindLogByKeyHash(sct.LogID.KeyID)
}

func init() {
	llData, err := ctx509util.ReadFileOrURL(ctlogs.LogListURL, http.DefaultClient)
	if err != nil {
		return
	}

	if loglist, err := ctlogs.NewFromJSON(llData); err == nil {
		ctLogList = loglist
	}
}
