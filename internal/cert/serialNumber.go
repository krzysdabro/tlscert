package cert

import (
	"math/big"
	"strings"
)

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
