// Java throughput runner. Times the from-scratch primitives under the uniform
// protocol (see ../README.md) and emits one JSON line per benchmark. Needs only the
// primitive classes (no Bouncy Castle, which the engine's KDFs use).
//
// Compile against the Java port's built classes, then run:
//   (cd ../../java && ./gradlew classes)
//   javac -cp ../../java/build/classes/java/main -d . Bench.java
//   java  -cp ../../java/build/classes/java/main:. Bench [buf] [warmup_s] [measure_s]

import com.alleato.dorado.Blake3;
import com.alleato.dorado.Skein;
import com.alleato.dorado.Threefish;

public class Bench {
    static int bufBytes = 1048576;

    interface Op {
        void run();
    }

    // Report peak throughput across many batches (max MB/s is the reproducible rate;
    // jitter only ever slows a batch). The clock is read only at batch boundaries.
    static void bench(String name, double warmup, double measure, Op op) {
        long start = System.nanoTime();
        while ((System.nanoTime() - start) / 1e9 < warmup) {
            op.run();
        }
        long batch = 1;
        while (true) {
            start = System.nanoTime();
            for (long i = 0; i < batch; i++) {
                op.run();
            }
            if ((System.nanoTime() - start) / 1e9 >= 0.1) {
                break;
            }
            batch *= 2;
        }
        double best = 0.0;
        long total = 0;
        long t0 = System.nanoTime();
        while ((System.nanoTime() - t0) / 1e9 < measure) {
            start = System.nanoTime();
            for (long i = 0; i < batch; i++) {
                op.run();
            }
            double mbps = (double) bufBytes * batch / 1e6 / ((System.nanoTime() - start) / 1e9);
            if (mbps > best) {
                best = mbps;
            }
            total += batch;
        }
        System.out.printf("{\"impl\":\"java\",\"bench\":\"%s\",\"mbps\":%.2f,\"iters\":%d}%n", name, best, total);
    }

    static Op ctrOp(int variant, int keyLen, byte[] data) {
        byte[] key = new byte[keyLen];
        byte[] iv = new byte[keyLen];
        byte[] tweak = new byte[16];
        java.util.Arrays.fill(key, (byte) 7);
        java.util.Arrays.fill(iv, (byte) 1);
        return () -> {
            Threefish c = variant == 256 ? Threefish.t256(key, tweak)
                : variant == 512 ? Threefish.t512(key, tweak) : Threefish.t1024(key, tweak);
            c.ctrApply(iv, data);
        };
    }

    public static void main(String[] args) {
        bufBytes = args.length > 0 ? Integer.parseInt(args[0]) : 1048576;
        double warmup = args.length > 1 ? Double.parseDouble(args[1]) : 0.5;
        double measure = args.length > 2 ? Double.parseDouble(args[2]) : 2.0;

        byte[] data = new byte[bufBytes];

        bench("threefish-256-ctr", warmup, measure, ctrOp(256, 32, data));
        bench("threefish-512-ctr", warmup, measure, ctrOp(512, 64, data));
        bench("threefish-1024-ctr", warmup, measure, ctrOp(1024, 128, data));
        bench("skein-512", warmup, measure, () -> Skein.hash(32, data));
        bench("blake3", warmup, measure, () -> Blake3.hash(32, data));
    }
}
