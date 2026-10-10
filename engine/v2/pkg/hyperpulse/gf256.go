package hyperpulse

const fieldPolynomial = 0x11d

var (
	gfExp [510]byte
	gfLog [256]byte
)

func init() {
	value := 1
	for i := 0; i < 255; i++ {
		gfExp[i] = byte(value)
		gfLog[byte(value)] = byte(i)
		value <<= 1
		if value&0x100 != 0 {
			value ^= fieldPolynomial
		}
	}
	for i := 255; i < len(gfExp); i++ {
		gfExp[i] = gfExp[i-255]
	}
}

func gfAdd(a, b byte) byte {
	return a ^ b
}

func gfMul(a, b byte) byte {
	if a == 0 || b == 0 {
		return 0
	}
	return gfExp[int(gfLog[a])+int(gfLog[b])]
}

func gfInv(a byte) byte {
	if a == 0 {
		return 0
	}
	return gfExp[255-int(gfLog[a])]
}

func gfPow(a byte, exponent int) byte {
	if exponent == 0 {
		return 1
	}
	if a == 0 {
		return 0
	}
	power := (int(gfLog[a]) * exponent) % 255
	return gfExp[power]
}
