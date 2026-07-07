// libFuzzer harness for the dorado decrypt path. Feeds arbitrary bytes to the
// in-memory decrypt entrypoint; the fuzzer drives coverage of the header parser and
// the framing/MAC loop. Built with sanitizers via the FUZZ CMake option (needs Clang):
//
//   cmake -S . -B build-fuzz -DFUZZ=ON -DCMAKE_CXX_COMPILER=clang++
//   cmake --build build-fuzz
//   ./build-fuzz/dorado_fuzz                  # run with libFuzzer defaults
//   ./build-fuzz/dorado_fuzz -max_total_time=60
//   ./build-fuzz/dorado_fuzz corpus/          # replay a corpus directory
//
// decrypt_password returns std::expected, so there is nothing to free; a bad input
// is rejected (the std::unexpected branch) without running a KDF in the common case.
#include <cstddef>
#include <cstdint>
#include <span>

#include "dorado/engine.hpp"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  static const std::uint8_t pw[] = "pw-cross";
  std::span<const std::uint8_t> password(pw, sizeof pw - 1);
  std::span<const std::uint8_t> container(data, size);
  auto result = dorado::engine::decrypt_password(password, container);
  (void)result;
  return 0;
}
