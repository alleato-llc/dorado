# Java throughput runner

Times the Java port's from-scratch primitives and prints one JSON line per
benchmark. See [`../README.md`](../README.md) for the shared protocol and framing.

Java is an SDK with no CLI, but the micro-benchmark works at the **library** level,
so it benchmarks the port just like the others (see the project README's note on why
the throughput section covers Java but the end-to-end section will not).

## Build and run

```
# 1. build the Java port's classes (once, or after changes)
(cd ../../java && ./gradlew classes)
# 2. compile the runner against them, then run
javac -cp ../../java/build/classes/java/main -d . Bench.java
java  -cp ../../java/build/classes/java/main:. Bench [buf] [warmup_s] [measure_s]
# defaults: 1048576 0.5 2.0
```

## How it works

`Bench.java` is compiled against the Java port's built classes
(`java/build/classes/java/main`) and calls them directly: `Threefish.t256/t512/t1024`
+ `ctrApply`, `Skein.hash`, `Blake3.hash`. It needs **no** dependencies, not even
Bouncy Castle, because the primitives do not use the KDFs. `bench()` runs the
peak-of-batches protocol and prints the JSON.

## Language notes

- Timing uses `System.nanoTime()` (monotonic).
- The warmup phase matters here: it lets the JIT reach steady state before the clock
  starts, so Java is measured at its compiled speed rather than mid-interpretation.
- The runner uses the JVM's default JIT settings (no flags).
