// TypeScript throughput runner. Times the *pure-TypeScript* from-scratch primitives
// (the readable BigInt cipher), under the uniform protocol (see ../README.md), and
// emits one JSON line per benchmark.
//
// This measures the pure-TS code, not the WASM backend the Node CLI ships. The WASM
// path is the Rust cipher compiled to WebAssembly and is benchmarked separately as
// `wasm`. Run with the TypeScript port's tsx:
//   ../../ts/node_modules/.bin/tsx runner.ts [buffer_bytes] [warmup_s] [measure_s]

import { tsBackend } from "../../ts/src/engine/backend";
import { T256, T512, T1024, type Variant } from "../../ts/src/engine/format";
import * as skein from "../../ts/src/skein";
import * as blake3 from "../../ts/src/blake3";

let bufBytes = 1048576;

// Report peak throughput across many batches (max MB/s is the reproducible rate;
// jitter only ever slows a batch). The clock is read only at batch boundaries.
function bench(name: string, warmup: number, measure: number, op: () => void): void {
  const wstart = performance.now();
  while ((performance.now() - wstart) / 1000 < warmup) op();

  let batch = 1;
  for (;;) {
    const start = performance.now();
    for (let i = 0; i < batch; i++) op();
    if ((performance.now() - start) / 1000 >= 0.1) break;
    batch *= 2;
  }

  let best = 0;
  let total = 0;
  const t0 = performance.now();
  while ((performance.now() - t0) / 1000 < measure) {
    const start = performance.now();
    for (let i = 0; i < batch; i++) op();
    const mbps = (bufBytes * batch) / 1e6 / ((performance.now() - start) / 1000);
    if (mbps > best) best = mbps;
    total += batch;
  }
  process.stdout.write(`{"impl":"ts","bench":"${name}","mbps":${best.toFixed(2)},"iters":${total}}\n`);
}

function ctrOp(variant: Variant, keyLen: number, data: Uint8Array): () => void {
  const key = new Uint8Array(keyLen).fill(7);
  const iv = new Uint8Array(keyLen).fill(1);
  const tweak = new Uint8Array(16);
  return () => {
    tsBackend.ctr(variant, key, tweak, iv, data);
  };
}

function main(): void {
  const argv = process.argv.slice(2);
  bufBytes = argv[0] ? parseInt(argv[0], 10) : 1048576;
  const warmup = argv[1] ? parseFloat(argv[1]) : 0.5;
  const measure = argv[2] ? parseFloat(argv[2]) : 2.0;

  const data = new Uint8Array(bufBytes);

  bench("threefish-256-ctr", warmup, measure, ctrOp(T256, 32, data));
  bench("threefish-512-ctr", warmup, measure, ctrOp(T512, 64, data));
  bench("threefish-1024-ctr", warmup, measure, ctrOp(T1024, 128, data));
  bench("skein-512", warmup, measure, () => skein.hash(32, data));
  bench("blake3", warmup, measure, () => blake3.hash(32, data));
}

main();
