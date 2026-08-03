# Haskell throughput runner

Times the Haskell port's from-scratch primitives and prints one JSON line per
benchmark. See [`../README.md`](../README.md) for the shared protocol and framing.

## Build and run

```
ghc -O2 -i../../haskell/src Main.hs -o dorado-bench
./dorado-bench [buffer_bytes] [warmup_seconds] [measure_seconds]
# defaults: 1048576 0.5 2.0
```

## How it works

It is compiled **directly against the port's library sources** (`-i../../haskell/src`)
rather than through cabal. `Dorado.Threefish`, `Dorado.Skein`, and `Dorado.Blake3`
depend only on GHC boot packages (`bytestring`, `array`); `crypton` is pulled in by the
KDF and MAC modules, which this runner never touches. So a plain `ghc` invocation is
enough and no package database needs solving.

`runOp` dispatches to one primitive; `bench` runs it in a warmup-then-measure loop and
prints `buffer_bytes * iters / 1e6 / elapsed` MB/s as JSON.

## Language notes

- **Laziness is the hazard.** A returned thunk that nothing inspects measures nothing.
  Every op forces its result with `evaluate` — for a strict `ByteString` that is the
  whole computation, since `BS.concat` must materialize the bytes — and returns a byte
  that the batch loop xors into an accumulator. Without both, the timing loop would
  measure thunk allocation.
- Compiled `-O2`, matching the other native runners.
- Timing uses `GHC.Clock.getMonotonicTime`.
- The numbers are low next to the C-family ports. That is the honest result of an
  unoptimized pure-functional implementation (ST arrays, per-block `ByteString`
  concatenation), not a harness artifact — the same framing `../README.md` gives for
  every port here.
