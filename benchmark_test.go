package common

import "testing"

func BenchmarkMerkleHashCompleteOld(b *testing.B) {
	bss := make([][][]byte, 10)
	for i := 0; i < len(bss); i++ {
		bss[i] = RandomByteSlices(97, 32)
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		j := i % len(bss)
		_, _ = MerkleHashCompleteOld(bss[j], -1, nil)
	}

}

func BenchmarkMerkleHashComplete(b *testing.B) {
	bss := make([][][]byte, 10)
	for i := 0; i < len(bss); i++ {
		bss[i] = RandomByteSlices(97, 32)
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		j := i % len(bss)
		_, _ = MerkleHashComplete(bss[j], -1, nil)
	}
}
