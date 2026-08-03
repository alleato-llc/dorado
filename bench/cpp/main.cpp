// C++ throughput runner. Times the from-scratch primitives under the uniform protocol
// (see ../README.md) and emits one JSON line per benchmark. Compiled directly against
// the three primitive translation units (no engine), so it needs neither libargon2 nor
// OpenSSL — the same trick the C runner uses.
#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <span>
#include <vector>

#include "dorado/blake3.hpp"
#include "dorado/skein.hpp"
#include "dorado/threefish.hpp"

namespace {

using Clock = std::chrono::steady_clock;  // monotonic; never jumps

double secs_since(Clock::time_point t) {
    return std::chrono::duration<double>(Clock::now() - t).count();
}

// The Gota protocol these runners implement (see bench/README.md).
constexpr const char* kProtocol = "1.2.0";

enum class Op { Ctr, Skein, Blake3 };

// One unit of measured work. The CTR path re-keys per call exactly like the C
// runner's, so the two measure the same thing.
void run_op(Op op, dorado::Variant variant, std::span<const std::uint8_t> key,
            std::span<const std::uint8_t> iv, std::span<std::uint8_t> data) {
    switch (op) {
        case Op::Ctr: {
            const std::uint8_t tweak[16] = {};
            const dorado::Threefish tf(variant, key, tweak);
            tf.ctr_apply(iv, data);
            break;
        }
        case Op::Skein: {
            const auto out = dorado::skein::hash(32, data);
            data[0] ^= out[0];  // sink: keep the hash observable
            break;
        }
        case Op::Blake3: {
            const auto out = dorado::blake3::hash(32, data);
            data[0] ^= out[0];  // sink
            break;
        }
    }
}

// Report peak throughput across many batches (the max MB/s is the reproducible rate;
// jitter only ever slows a batch). The clock is read only at batch boundaries.
void bench(const char* name, Op op, dorado::Variant variant, std::span<const std::uint8_t> key,
           std::span<const std::uint8_t> iv, std::span<std::uint8_t> data, double warmup,
           double measure) {
    auto start = Clock::now();
    while (secs_since(start) < warmup) {
        run_op(op, variant, key, iv, data);
    }

    std::uint64_t batch = 1;
    for (;;) {
        start = Clock::now();
        for (std::uint64_t i = 0; i < batch; ++i) {
            run_op(op, variant, key, iv, data);
        }
        if (secs_since(start) >= 0.1) {
            break;
        }
        batch *= 2;
    }

    double best = 0.0;
    std::uint64_t total = 0;
    std::vector<double> samples;  // per-batch MB/s; median vs peak shows run stability
    const auto t0 = Clock::now();
    while (secs_since(t0) < measure) {
        start = Clock::now();
        for (std::uint64_t i = 0; i < batch; ++i) {
            run_op(op, variant, key, iv, data);
        }
        const double mbps = static_cast<double>(data.size()) * static_cast<double>(batch) / 1e6 /
                            secs_since(start);
        best = std::max(best, mbps);
        samples.push_back(mbps);
        total += batch;
    }

    std::sort(samples.begin(), samples.end());
    const std::size_t n = samples.size();
    const double median =
        n == 0 ? 0.0 : (n % 2 ? samples[n / 2] : (samples[n / 2 - 1] + samples[n / 2]) / 2);

    std::printf(
        "{\"impl\":\"cpp\",\"bench\":\"%s\",\"mbps\":%.2f,\"mbps_median\":%.2f,\"iters\":%llu,\"protocol\":\"%s\"}\n",
        name, best, median, static_cast<unsigned long long>(total), kProtocol);
}

}  // namespace

int main(int argc, char** argv) {
    const std::size_t n =
        argc > 1 ? static_cast<std::size_t>(std::strtoull(argv[1], nullptr, 10)) : 1048576;
    const double warmup = argc > 2 ? std::atof(argv[2]) : 0.5;
    const double measure = argc > 3 ? std::atof(argv[3]) : 2.0;

    std::vector<std::uint8_t> data(n, 0);
    std::vector<std::uint8_t> key(128, 7);
    std::vector<std::uint8_t> iv(128, 1);

    const std::span<std::uint8_t> buf(data);
    const std::span<const std::uint8_t> key_span(key);
    const std::span<const std::uint8_t> iv_span(iv);

    // Each variant takes a key of its own width; the CTR IV is one block wide.
    bench("threefish-256-ctr", Op::Ctr, dorado::Variant::TF256, key_span.first(32),
          iv_span.first(32), buf, warmup, measure);
    bench("threefish-512-ctr", Op::Ctr, dorado::Variant::TF512, key_span.first(64),
          iv_span.first(64), buf, warmup, measure);
    bench("threefish-1024-ctr", Op::Ctr, dorado::Variant::TF1024, key_span.first(128),
          iv_span.first(128), buf, warmup, measure);
    bench("skein-512", Op::Skein, dorado::Variant::TF512, key_span, iv_span, buf, warmup, measure);
    bench("blake3", Op::Blake3, dorado::Variant::TF512, key_span, iv_span, buf, warmup, measure);

    return 0;
}
