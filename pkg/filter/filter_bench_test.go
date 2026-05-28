//go:build linux

package filter

import (
	"os"
	"testing"
)

func BenchmarkCgroupGetStats(b *testing.B) {
	requireRootBenchmark(b)

	objs := &cgroupObjects{}
	if err := loadCgroupObjects(objs, nil); err != nil {
		b.Skipf("loading cgroup BPF objects: %v", err)
	}
	defer objs.Close()

	f := &CgroupFilter{objs: objs}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := f.GetStats(); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkTCGetStats(b *testing.B) {
	requireRootBenchmark(b)

	objs := &tcObjects{}
	if err := loadTcObjects(objs, nil); err != nil {
		b.Skipf("loading TC BPF objects: %v", err)
	}
	defer objs.Close()

	f := &TCFilter{objs: objs}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := f.GetStats(); err != nil {
			b.Fatal(err)
		}
	}
}

func requireRootBenchmark(b *testing.B) {
	b.Helper()
	if os.Geteuid() != 0 {
		b.Skip("benchmark requires root")
	}
}
