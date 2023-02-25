package pricers

import "testing"

func Benchmark_Square(b *testing.B) {
	var pad []byte = []byte{1, 2, 3, 4, 5, 6, 7, 8}[:8]
	var p []byte = []byte{1, 2, 3, 4, 5, 6, 7, 8}[:8]
	for i := 0; i < b.N; i++ {
		Square(pad, p)
	}
}

func Benchmark_Square2(b *testing.B) {
	var pad []byte = []byte{1, 2, 3, 4, 5, 6, 7, 8}[:8]
	var p []byte = []byte{1, 2, 3, 4, 5, 6, 7, 8}[:8]
	for i := 0; i < b.N; i++ {
		Square2(pad, p)
	}
}
