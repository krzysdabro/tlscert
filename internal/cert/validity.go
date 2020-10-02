package cert

import (
	"fmt"
)

type certValidity struct {
	err error
}

func (cv certValidity) Valid() bool {
	return cv.err == nil
}

func (cv certValidity) String() string {
	if cv.Valid() {
		return "yes"
	}
	return fmt.Sprintf("no (%s)", cv.err.Error())
}
