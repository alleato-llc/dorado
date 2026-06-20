#!/usr/bin/env python3
"""Python throughput runner. Times the from-scratch primitives under the uniform
protocol (see ../README.md) and emits one JSON line per benchmark.

Run inside the Python port's venv (where `dorado` is installed):
    python runner.py [buffer_bytes] [warmup_seconds] [measure_seconds]
"""

from __future__ import annotations

import sys
import time

from dorado import blake3, skein, threefish

BUF_BYTES = 1048576


def bench(name: str, warmup: float, measure: float, op) -> None:
    # Report peak throughput across many batches (max MB/s is the reproducible rate;
    # jitter only ever slows a batch). The clock is read only at batch boundaries.
    start = time.perf_counter()
    while time.perf_counter() - start < warmup:
        op()
    batch = 1
    while True:
        start = time.perf_counter()
        for _ in range(batch):
            op()
        if time.perf_counter() - start >= 0.1:
            break
        batch *= 2
    best = 0.0
    total = 0
    t0 = time.perf_counter()
    while time.perf_counter() - t0 < measure:
        start = time.perf_counter()
        for _ in range(batch):
            op()
        mbps = BUF_BYTES * batch / 1e6 / (time.perf_counter() - start)
        if mbps > best:
            best = mbps
        total += batch
    print(f'{{"impl":"python","bench":"{name}","mbps":{best:.2f},"iters":{total}}}', flush=True)


def ctr_op(factory, key_len: int, data: bytes):
    key = bytes([7]) * key_len
    iv = bytes([1]) * key_len
    tweak = bytes(16)

    def op():
        factory(key, tweak).ctr_apply(iv, data)

    return op


def main() -> None:
    global BUF_BYTES
    BUF_BYTES = int(sys.argv[1]) if len(sys.argv) > 1 else 1048576
    warmup = float(sys.argv[2]) if len(sys.argv) > 2 else 0.5
    measure = float(sys.argv[3]) if len(sys.argv) > 3 else 2.0

    data = bytes(BUF_BYTES)

    bench("threefish-256-ctr", warmup, measure, ctr_op(threefish.Threefish.t256, 32, data))
    bench("threefish-512-ctr", warmup, measure, ctr_op(threefish.Threefish.t512, 64, data))
    bench("threefish-1024-ctr", warmup, measure, ctr_op(threefish.Threefish.t1024, 128, data))
    bench("skein-512", warmup, measure, lambda: skein.hash(32, data))
    bench("blake3", warmup, measure, lambda: blake3.hash(32, data))


if __name__ == "__main__":
    main()
