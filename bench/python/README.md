# Python throughput runner

Times the Python port's from-scratch primitives and prints one JSON line per
benchmark. See [`../README.md`](../README.md) for the shared protocol and framing.

## Build and run

It needs the `dorado` package importable, easiest via the Python port's venv:

```
# one-time: make the venv and install the port
(cd ../../python && python3 -m venv .venv && . .venv/bin/activate && pip install -e .)
# run (the orchestrator finds ../python/.venv automatically)
../../python/.venv/bin/python runner.py [buffer_bytes] [warmup_seconds] [measure_seconds]
# defaults: 1048576 0.5 2.0
```

## How it works

It imports the installed package (`from dorado import threefish, skein, blake3`) and
calls `threefish.Threefish.t256/t512/t1024(...).ctr_apply(iv, data)`,
`skein.hash(32, data)`, `blake3.hash(32, data)`. `bench()` runs the peak-of-batches
protocol and prints the JSON.

## Language notes

- Timing uses `time.perf_counter()` (monotonic, high resolution).
- This is the slowest port by far (~0.6 MB/s for the cipher): pure-Python
  arbitrary-precision integers masked to 2**64 are ~100x slower than native `u64`.
  BLAKE3 is faster (~1.4 MB/s) because its 32-bit words fit native ints without the
  bignum tax. This is the honest cost of a readable reference implementation in
  Python, not a bug.
- Because Python is slow, a full run spends most of its wall time here; the 64 KiB
  default buffer keeps it to many short batches rather than one long one.
