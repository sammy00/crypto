package ecdsa

// ReverseCopy fill bytes from src into dst from end to start
func ReverseCopy(dst, src []byte) {
	offset := len(dst) - len(src)
	if offset >= 0 {
		copy(dst[offset:], src)
	} else {
		copy(dst, src[-offset:])
	}
}
