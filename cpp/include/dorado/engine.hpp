// The DRDO password container: encrypt-then-MAC over a continuous CTR stream,
// framed into chunks, plus raw-key CTR and inspect. Streaming over std::istream/
// std::ostream in constant memory; in-memory byte forms wrap the streaming core.
// Cross-compatible with the other ports' containers.
#pragma once

#include <cstddef>
#include <cstdint>
#include <expected>
#include <istream>
#include <optional>
#include <ostream>
#include <span>
#include <string>
#include <vector>

#include "dorado/kdf.hpp"
#include "dorado/mac.hpp"
#include "dorado/threefish.hpp"

namespace dorado::engine {

struct Options {
  Variant variant = Variant::TF256;
  kdf::Kdf kdf = kdf::Argon2id{65536, 3, 1};  // 64 MiB, 3 passes, 1 lane
  mac::Mac mac = mac::Mac::Skein512;
  std::uint32_t chunk_size = 65536;
  std::vector<std::uint8_t> label;
};

inline Options default_options() { return Options{}; }

using Bytes = std::vector<std::uint8_t>;
using Span = std::span<const std::uint8_t>;
template <class T>
using Result = std::expected<T, std::string>;

// Random bytes from the system CSPRNG (OpenSSL RAND_bytes).
void random_bytes(std::span<std::uint8_t> out);

// --- streaming (constant memory) ---
void encrypt_password_stream(const Options& opts, Span salt, Span tweak, Span iv, Span password,
                             std::istream& in, std::ostream& out);
Result<void> decrypt_password_stream(Span password, std::optional<Span> expect_label,
                                     std::istream& in, std::ostream& out);
Result<void> raw_ctr_stream(Span key, Span tweak, Span iv, std::istream& in, std::ostream& out);

// Raw-key authenticated CTR (encrypt-then-MAC, caller-supplied key, no password
// or KDF): reuses the password container's frame layout and MAC pattern, but
// binds the tweak and IV into frame 0's AAD instead of a header (there is none
// here). Unlike raw_ctr_stream, a wrong key or a tampered/corrupted stream is
// reported as an error instead of silently producing garbage. See
// ../docs/spec.md's "Raw-key modes" section. Bare raw_ctr_stream is unchanged
// and stays the default.
Result<void> encrypt_raw_authenticated_stream(Variant variant, Span key, Span tweak, Span iv,
                                              mac::Mac mac, std::uint32_t chunk_size,
                                              std::istream& in, std::ostream& out);
Result<void> decrypt_raw_authenticated_stream(Variant variant, Span key, Span tweak, Span iv,
                                              mac::Mac mac, std::uint32_t chunk_size,
                                              std::istream& in, std::ostream& out);

// --- in-memory ---
Bytes encrypt_password_with(const Options& opts, Span salt, Span tweak, Span iv, Span password,
                            Span plaintext);
Bytes encrypt_password(const Options& opts, Span tweak, Span password, Span plaintext);
Result<Bytes> decrypt_password(Span password, Span container);
Result<Bytes> decrypt_password_expecting(Span password, std::optional<Span> expect_label,
                                         Span container);
Result<Bytes> raw_ctr(Span key, Span tweak, Span iv, Span data);
Result<Bytes> encrypt_raw_authenticated(Variant variant, Span key, Span tweak, Span iv,
                                        mac::Mac mac, std::uint32_t chunk_size, Span plaintext);
Result<Bytes> decrypt_raw_authenticated(Variant variant, Span key, Span tweak, Span iv,
                                        mac::Mac mac, std::uint32_t chunk_size, Span data);

struct ContainerInfo {
  std::uint8_t version;
  Variant variant;
  kdf::Kdf kdf;
  mac::Mac mac;
  std::uint32_t chunk_size;
  std::size_t salt_len;
  Bytes tweak;
  Bytes label;
};
Result<ContainerInfo> inspect(Span container);

}  // namespace dorado::engine
