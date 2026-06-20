// Go throughput runner. Times the from-scratch primitives under the uniform protocol
// (see ../README.md) and emits one JSON line per benchmark.
package main

import (
	"crypto/cipher"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/alleato-llc/dorado/go/blake3"
	"github.com/alleato-llc/dorado/go/skein"
	"github.com/alleato-llc/dorado/go/threefish"
)

// Report peak throughput across many batches (max MB/s is the reproducible rate;
// jitter only ever slows a batch). The clock is read only at batch boundaries.
func bench(name string, warmup, measure time.Duration, op func()) {
	start := time.Now()
	for time.Since(start) < warmup {
		op()
	}
	var batch uint64 = 1
	for {
		start = time.Now()
		for i := uint64(0); i < batch; i++ {
			op()
		}
		if time.Since(start) >= 100*time.Millisecond {
			break
		}
		batch *= 2
	}
	best := 0.0
	var total uint64
	t0 := time.Now()
	for time.Since(t0) < measure {
		start = time.Now()
		for i := uint64(0); i < batch; i++ {
			op()
		}
		mbps := float64(bufBytes) * float64(batch) / 1e6 / time.Since(start).Seconds()
		if mbps > best {
			best = mbps
		}
		total += batch
	}
	fmt.Printf("{\"impl\":\"go\",\"bench\":\"%s\",\"mbps\":%.2f,\"iters\":%d}\n", name, best, total)
}

var bufBytes int

func ctrOp(newBlock func(key, tweak []byte) (cipher.Block, error), keyLen int, data []byte) func() {
	key := make([]byte, keyLen)
	iv := make([]byte, keyLen)
	tweak := make([]byte, 16)
	for i := range key {
		key[i] = 7
		iv[i] = 1
	}
	return func() {
		block, _ := newBlock(key, tweak)
		cipher.NewCTR(block, iv).XORKeyStream(data, data)
	}
}

func main() {
	bufBytes = 1048576
	warmup := 0.5
	measure := 2.0
	if len(os.Args) > 1 {
		bufBytes, _ = strconv.Atoi(os.Args[1])
	}
	if len(os.Args) > 2 {
		warmup, _ = strconv.ParseFloat(os.Args[2], 64)
	}
	if len(os.Args) > 3 {
		measure, _ = strconv.ParseFloat(os.Args[3], 64)
	}
	w := time.Duration(warmup * float64(time.Second))
	m := time.Duration(measure * float64(time.Second))

	data := make([]byte, bufBytes)
	out32 := make([]byte, 32)

	bench("threefish-256-ctr", w, m, ctrOp(threefish.New256, 32, data))
	bench("threefish-512-ctr", w, m, ctrOp(threefish.New512, 64, data))
	bench("threefish-1024-ctr", w, m, ctrOp(threefish.New1024, 128, data))
	bench("skein-512", w, m, func() { _ = skein.Hash(32, data) })
	bench("blake3", w, m, func() { blake3.Hash(out32, data) })
}
