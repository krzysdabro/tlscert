package certutil

import (
	"encoding/asn1"
	"fmt"
	"reflect"
	"strings"
)

var (
	OIDQCStatementsExt = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 3}

	OIDQCSyntaxV1 = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 11, 1}
	OIDQCSyntaxV2 = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 11, 2}

	knownStatements = map[string]statementDescription{
		"0.4.0.1862.1.1": {"ETSI QcCompliance", nil},
		"0.4.0.1862.1.5": {"ETSI QcPDS", &[]struct {
			URL      string
			Language string
		}{}},
		"0.4.0.1862.1.6": {"ETSI QcType", &etsiQcType{}},
	}
)

type etsiQcType []asn1.ObjectIdentifier

func (s etsiQcType) String() string {
	switch s[0].String() {
	case "0.4.0.1862.1.6.1":
		return "ETSI qct-esign"
	case "0.4.0.1862.1.6.2":
		return "ETSI qct-eseal"
	case "0.4.0.1862.1.6.3":
		return "ETSI qct-web"
	}

	return s[0].String()
}

type statementDescription struct {
	Name   string
	Syntax interface{}
}

type QCStatement struct {
	ID             asn1.ObjectIdentifier
	RawInformation asn1.RawValue `asn1:"optional,omitempty"`
}

func ParseQCStatement(raw []byte) ([]QCStatement, error) {
	var statements []QCStatement
	_, err := asn1.Unmarshal(raw, &statements)
	if err != nil {
		return statements, err
	}

	return statements, nil
}

func (s *QCStatement) ParseInformation(val interface{}) error {
	if len(s.RawInformation.FullBytes) == 0 {
		return fmt.Errorf("qcstatements: empty information for %s", s.ID)
	}

	if _, err := asn1.Unmarshal(s.RawInformation.FullBytes, val); err != nil {
		return fmt.Errorf("qcstatements: semantics info: %w", err)
	}

	return nil
}

func (s *QCStatement) String() string {
	b := strings.Builder{}
	if desc, ok := knownStatements[s.ID.String()]; ok {
		b.WriteString(desc.Name)

		if desc.Syntax != nil {
			val := reflect.New(reflect.ValueOf(desc.Syntax).Elem().Type()).Interface()
			b.WriteString(" = ")

			err := s.ParseInformation(val)
			if err != nil {
				b.WriteString(err.Error())
			} else {
				v := reflect.ValueOf(val).Elem()
				if str, ok := v.Interface().(fmt.Stringer); ok {
					b.WriteString(str.String())
				} else if v.Len() == 1 {
					b.WriteString(fmt.Sprintf("%s", v.Index(0).Interface()))
				} else {
					b.WriteString(fmt.Sprintf("%s", v.Interface()))
				}
			}
		}
	} else {
		b.WriteString(s.ID.String())
	}

	return b.String()
}
