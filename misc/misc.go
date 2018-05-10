package misc

import "math/big"

// IsOdd checks if a given big integer is odd
func IsOdd(n *big.Int) bool {
	return 1 == n.Bit(0)
}

// ReverseCopy fill bytes from src into dst from end to start
func ReverseCopy(dst, src []byte) {
	offset := len(dst) - len(src)
	if offset >= 0 {
		copy(dst[offset:], src)
	} else {
		copy(dst, src[-offset:])
	}
}
