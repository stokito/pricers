package pricers

import "encoding/binary"

func Square(pad, p []byte) uint64 {
	padLong := binary.BigEndian.Uint64(pad)
	pLong := binary.BigEndian.Uint64(p)
	priceInMicros := padLong ^ pLong
	return priceInMicros
}

func Square2(pad, p []byte) uint64 {
	var priceMicro [8]byte
	for i := 0; i < 8; i++ {
		priceMicro[i] = pad[i] ^ p[i]
	}
	priceInMicros := binary.BigEndian.Uint64(priceMicro[:])
	return priceInMicros
}

func maind() {
	var pad []byte = []byte{1, 2, 3, 4, 5, 6, 7, 8}[:8]
	var p []byte = []byte{1, 2, 3, 4, 5, 6, 7, 8}[:8]
	Square(pad, p)
	Square2(pad, p)
}
