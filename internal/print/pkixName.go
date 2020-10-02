package print

import "crypto/x509/pkix"

// PkixName prints common fields of X.509 distinguished name.
func PkixName(field string, name pkix.Name) {
	Field(field, "")
	if name.CommonName != "" {
		List("  Common Name", []string{name.CommonName})
	}
	List("  Organization Unit", name.OrganizationalUnit)
	List("  Organization", name.Organization)
	List("  Postal Code", name.PostalCode)
	List("  Street Address", name.StreetAddress)
	List("  Locality", name.Locality)
	List("  State/Province", name.Province)
	List("  Country", name.Country)
}
