package print

import (
	"fmt"
	"strings"
)

var separator = strings.Repeat("-", 30)

// Field prints single field and value.
func Field(field, value string) {
	fmt.Printf("%-22s  %s\n", field, value)
}

// List prints multi-value fields.
func List(field string, list []string) {
	for _, item := range list {
		Field(field, item)
	}
}

// Separator prints separator between certs.
func Separator() {
	fmt.Println(separator)
}
