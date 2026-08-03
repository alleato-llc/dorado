#include "dorado/engine.hpp"

#include <openssl/rand.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <charconv>
#include <cstdlib>
#include <sstream>
#include <stdexcept>
#include <utility>

#include "dorado/format.hpp"
#include "dorado/skein.hpp"
#include "internal.hpp"

namespace dorado::engine {
namespace {

constexpr std::array<std::uint8_t, 8> kDomain = {'D', 'R', 'D', 'O', 'c', 'h', 'n', 'k'};

// Domain separators for the raw-key authenticated construction (encrypt-then-MAC
// over a caller-supplied key, no password or KDF). Distinct from `kDomain` (the
// password container's frame domain) so a raw-mode frame's tag can never collide
// with or be replayed as a password-mode frame's tag, even under key reuse.
constexpr std::array<std::uint8_t, 8> kRawAuthEncDomain = {'D', 'R', 'D', 'O', 'r', 'a', 'w', 'E'};
constexpr std::array<std::uint8_t, 8> kRawAuthMacDomain = {'D', 'R', 'D', 'O', 'r', 'a', 'w', 'M'};
constexpr std::array<std::uint8_t, 8> kRawFrameDomain = {'D', 'R', 'D', 'O', 'r', 'w', 'F', 'r'};

// Run a cleanup action on scope exit (the C++ analog of C's cleanup attribute).
template <class F>
struct ScopeExit {
  F f;
  ~ScopeExit() { f(); }
};
template <class F>
ScopeExit(F) -> ScopeExit<F>;

void put_u32be(std::vector<std::uint8_t>& o, std::uint32_t w) {
  for (int i = 3; i >= 0; --i) o.push_back(std::uint8_t(w >> (8 * i)));
}
void put_u64be(std::vector<std::uint8_t>& o, std::uint64_t w) {
  for (int i = 7; i >= 0; --i) o.push_back(std::uint8_t(w >> (8 * i)));
}

Bytes frame_aad(Span header_bytes, std::uint64_t idx, bool is_last, Span ct) {
  Bytes aad(kDomain.begin(), kDomain.end());
  if (idx == 0) aad.insert(aad.end(), header_bytes.begin(), header_bytes.end());
  put_u64be(aad, idx);
  aad.push_back(is_last ? 1 : 0);
  put_u32be(aad, std::uint32_t(ct.size()));
  aad.insert(aad.end(), ct.begin(), ct.end());
  return aad;
}

// Authenticated data for a raw-mode frame: a domain separator, the tweak and IV
// (for frame index 0 only, binding the parameters since raw mode has no header
// to bind them into the way the password container does), the index, the last
// flag, and the ciphertext. Mirrors `frame_aad`, substituting tweak+IV for the
// header.
Bytes raw_frame_aad(Span tweak, Span iv, std::uint64_t idx, bool is_last, Span ct) {
  Bytes aad(kRawFrameDomain.begin(), kRawFrameDomain.end());
  if (idx == 0) {
    aad.insert(aad.end(), tweak.begin(), tweak.end());
    aad.insert(aad.end(), iv.begin(), iv.end());
  }
  put_u64be(aad, idx);
  aad.push_back(is_last ? 1 : 0);
  put_u32be(aad, std::uint32_t(ct.size()));
  aad.insert(aad.end(), ct.begin(), ct.end());
  return aad;
}

bool ct_eq(Span a, Span b) {
  if (a.size() != b.size()) return false;
  std::uint8_t d = 0;
  for (std::size_t i = 0; i < a.size(); ++i) d |= a[i] ^ b[i];
  return d == 0;
}

// Advance a big-endian counter by `blocks`, wrapping at the IV width.
void iv_advance(std::vector<std::uint8_t>& iv, std::uint64_t blocks) {
  std::uint64_t add = blocks, carry = 0;
  for (int i = int(iv.size()) - 1; i >= 0 && (add > 0 || carry > 0); --i) {
    std::uint64_t sum = std::uint64_t(iv[i]) + (add & 0xff) + carry;
    iv[i] = std::uint8_t(sum);
    carry = sum >> 8;
    add >>= 8;
  }
}

struct Keys {
  Bytes enc, mac;
};
// Throws std::runtime_error if the KDF itself fails. Callers on the decrypt path run
// kdf::validate first, so a malformed header is rejected before reaching here; this
// remains a throwing helper only for genuinely exceptional backend failures, which the
// public entrypoints convert into an error rather than letting escape (see the
// try/catch around the decrypt path).
Keys derive_keys(const kdf::Kdf& k, Span password, Span salt, int key_len) {
  auto out = kdf::derive(k, password, salt, std::size_t(key_len) + 32);
  Keys keys{Bytes(out.begin(), out.begin() + key_len), Bytes(out.begin() + key_len, out.end())};
  detail::secure_wipe(out.data(), out.size());  // the combined keymat copy
  return keys;
}

// Wipe a Keys' enc and mac buffers (their backing storage holds secret material).
void wipe_keys(Keys& k) {
  detail::secure_wipe(k.enc.data(), k.enc.size());
  detail::secure_wipe(k.mac.data(), k.mac.size());
}

// Split a caller-supplied raw key into an independent encryption subkey and MAC
// subkey, each derived via domain-separated Skein-512 keyed hashing (`key` is
// the MAC key, the domain label is the message). Deliberately not a password
// KDF: `key` is assumed to already be high-entropy (an OS keychain or a CSPRNG),
// so no cost-parameterized stretching is needed, only separation into two
// subkeys that must not be the same bytes used for two different primitives.
Result<Keys> split_raw_key(Variant variant, Span key) {
  int key_len = key_size(variant);
  if (int(key.size()) != key_len) {
    return std::unexpected("raw key must be " + std::to_string(key_len) +
                           " bytes for this variant, got " + std::to_string(key.size()));
  }
  Bytes enc = skein::mac(key, std::size_t(key_len),
                        Span(kRawAuthEncDomain.data(), kRawAuthEncDomain.size()));
  Bytes mk = skein::mac(key, 32, Span(kRawAuthMacDomain.data(), kRawAuthMacDomain.size()));
  return Keys{std::move(enc), std::move(mk)};
}

// Validate the IV and chunk size shared by the raw-authenticated encrypt and
// decrypt paths.
Result<void> validate_raw_auth_params(Variant variant, Span iv, std::uint32_t chunk_size) {
  int bs = block_size(variant);
  if (int(iv.size()) != bs) {
    return std::unexpected("iv must be " + std::to_string(bs) + " bytes for this variant, got " +
                           std::to_string(iv.size()));
  }
  if (chunk_size == 0 || chunk_size % std::uint32_t(bs) != 0) {
    return std::unexpected("chunk size must be a positive multiple of the block size (" +
                           std::to_string(bs) + "), got " + std::to_string(chunk_size));
  }
  return {};
}

// Read up to n bytes from `in`, appending to `out`. Returns true iff it got n.
bool read_up_to(std::istream& in, Bytes& out, std::size_t n) {
  std::size_t start = out.size();
  out.resize(start + n);
  in.read(reinterpret_cast<char*>(out.data() + start), std::streamsize(n));
  std::size_t got = std::size_t(in.gcount());
  out.resize(start + got);
  return got == n;
}

void write_bytes(std::ostream& out, Span b) {
  out.write(reinterpret_cast<const char*>(b.data()), std::streamsize(b.size()));
}

}  // namespace

void random_bytes(std::span<std::uint8_t> out) {
  if (RAND_bytes(out.data(), int(out.size())) != 1) throw std::runtime_error("RAND_bytes failed");
}

std::uint32_t max_chunk_bytes() {
  const char* s = std::getenv("DORADO_MAX_CHUNK_BYTES");
  return chunk_cap_from(s ? std::optional<std::string_view>(s) : std::nullopt);
}

std::uint32_t chunk_cap_from(std::optional<std::string_view> override_opt) {
  if (!override_opt) return kDefaultMaxChunkBytes;
  std::string_view s = *override_opt;
  while (!s.empty() && std::isspace(static_cast<unsigned char>(s.front()))) s.remove_prefix(1);
  while (!s.empty() && std::isspace(static_cast<unsigned char>(s.back()))) s.remove_suffix(1);
  std::uint32_t v = 0;
  auto [end, ec] = std::from_chars(s.data(), s.data() + s.size(), v);
  if (ec != std::errc() || end != s.data() + s.size()) return kDefaultMaxChunkBytes;
  return std::clamp(v, std::uint32_t(1), kMaxChunkBytes);
}

void encrypt_password_stream(const Options& opts, Span salt, Span tweak, Span iv, Span password,
                             std::istream& in, std::ostream& out) {
  int key_len = key_size(opts.variant);
  Keys keys = derive_keys(opts.kdf, password, salt, key_len);
  ScopeExit wipe{[&] { wipe_keys(keys); }};  // scrub keys on every exit path
  Threefish tf(opts.variant, keys.enc, tweak);
  std::size_t cs = opts.chunk_size;
  std::uint64_t bpc = cs / block_size(opts.variant);

  format::Header h{4,
                   opts.variant,
                   opts.kdf,
                   opts.mac,
                   opts.chunk_size,
                   Bytes(salt.begin(), salt.end()),
                   Bytes(tweak.begin(), tweak.end()),
                   Bytes(iv.begin(), iv.end()),
                   opts.label};
  auto header_bytes = format::serialize(h);
  write_bytes(out, header_bytes);

  std::vector<std::uint8_t> counter(iv.begin(), iv.end());
  Bytes cur;
  read_up_to(in, cur, cs);
  std::uint64_t idx = 0;
  for (;;) {
    Bytes next;
    read_up_to(in, next, cs);
    bool is_last = next.empty();
    Bytes ct = cur;
    tf.ctr_apply(counter, ct);
    auto tag = mac::tag(opts.mac, keys.mac, frame_aad(header_bytes, idx, is_last, ct));
    std::uint8_t lastb = is_last ? 1 : 0;
    out.write(reinterpret_cast<const char*>(&lastb), 1);
    Bytes lenb;
    put_u32be(lenb, std::uint32_t(ct.size()));
    write_bytes(out, lenb);
    write_bytes(out, ct);
    write_bytes(out, tag);
    if (is_last) break;
    iv_advance(counter, bpc);
    cur = std::move(next);
    ++idx;
  }
}

Result<void> decrypt_password_stream(Span password, std::optional<Span> expect, std::istream& in,
                                     std::ostream& out) {
  // Accumulate bytes until the header parses; the leftover is the start of frames.
  Bytes pending;
  format::Header header;
  std::size_t consumed = 0;
  for (;;) {
    auto pr = format::parse(pending);
    if (pr) {
      header = std::move(pr->header);
      consumed = pr->consumed;
      break;
    }
    if (pr.error().find("end of input") == std::string::npos) return std::unexpected(pr.error());
    Bytes more;
    read_up_to(in, more, 256);
    if (more.empty()) return std::unexpected("truncated header");
    pending.insert(pending.end(), more.begin(), more.end());
  }
  Bytes header_raw(pending.begin(), pending.begin() + consumed);
  Bytes leftover(pending.begin() + consumed, pending.end());

  if (expect && !std::equal(expect->begin(), expect->end(), header.label.begin(), header.label.end()))
    return std::unexpected("label mismatch");

  // Bound the header's chunk size (which bounds every frame allocation) and the
  // KDF cost before deriving any key: both come from an untrusted header, so
  // without these a crafted file could demand a huge allocation or a
  // multi-minute, multi-gigabyte derivation (a denial of service).
  int bs = block_size(header.variant);
  if (header.chunk_size == 0 || header.chunk_size > max_chunk_bytes() ||
      header.chunk_size % std::uint32_t(bs) != 0)
    return std::unexpected("invalid chunk size " + std::to_string(header.chunk_size) +
                           " in header");
  if (auto v = kdf::validate(header.kdf); !v) return std::unexpected(v.error());

  int key_len = key_size(header.variant);
  Keys keys = derive_keys(header.kdf, password, header.salt, key_len);
  ScopeExit wipe{[&] { wipe_keys(keys); }};  // scrub keys on every exit path
  Threefish tf(header.variant, keys.enc, header.tweak);
  std::uint64_t bpc = header.chunk_size / block_size(header.variant);
  std::vector<std::uint8_t> counter(header.iv.begin(), header.iv.end());

  std::size_t lpos = 0;
  auto read_n = [&](std::size_t n) -> std::optional<Bytes> {
    Bytes r;
    std::size_t take = std::min(n, leftover.size() - lpos);
    r.insert(r.end(), leftover.begin() + lpos, leftover.begin() + lpos + take);
    lpos += take;
    if (r.size() < n) read_up_to(in, r, n - r.size());
    return r.size() == n ? std::optional<Bytes>(std::move(r)) : std::nullopt;
  };

  std::uint64_t idx = 0;
  for (;;) {
    auto is_last_b = read_n(1);
    if (!is_last_b) return std::unexpected("truncated: no final frame before end of input");
    auto len_b = read_n(4);
    if (!len_b) return std::unexpected("truncated frame");
    std::uint32_t ct_len = 0;
    for (int i = 0; i < 4; ++i) ct_len = ct_len << 8 | (*len_b)[i];
    if (ct_len > header.chunk_size) return std::unexpected("frame ct_len exceeds chunk size");
    auto ct = read_n(ct_len);
    if (!ct) return std::unexpected("truncated frame");
    auto tag = read_n(32);
    if (!tag) return std::unexpected("truncated frame");
    bool is_last = (*is_last_b)[0] == 1;
    auto expected = mac::tag(header.mac, keys.mac, frame_aad(header_raw, idx, is_last, *ct));
    if (!ct_eq(expected, *tag)) return std::unexpected("authentication failed");
    if (!is_last && ct->size() != header.chunk_size)
      return std::unexpected("non-final frame is not a full chunk");
    Bytes pt = *ct;
    tf.ctr_apply(counter, pt);
    write_bytes(out, pt);
    if (is_last) return {};
    iv_advance(counter, bpc);
    ++idx;
  }
}

Result<void> raw_ctr_stream(Span key, Span tweak, Span iv, std::istream& in, std::ostream& out) {
  Variant v;
  switch (key.size()) {
    case 32: v = Variant::TF256; break;
    case 64: v = Variant::TF512; break;
    case 128: v = Variant::TF1024; break;
    default: return std::unexpected("key length must be 32, 64, or 128 bytes");
  }
  if (int(iv.size()) != block_size(v)) return std::unexpected("iv must be the same length as the key");
  if (tweak.size() != 16) return std::unexpected("tweak must be 16 bytes");
  Threefish tf(v, key, tweak);
  std::size_t bs = block_size(v);
  std::size_t buf = 65536 - (65536 % bs);
  std::uint64_t bpb = buf / bs;
  std::vector<std::uint8_t> counter(iv.begin(), iv.end());
  for (;;) {
    Bytes chunk;
    bool full = read_up_to(in, chunk, buf);
    if (chunk.empty()) break;
    tf.ctr_apply(counter, chunk);
    write_bytes(out, chunk);
    if (!full) break;
    iv_advance(counter, bpb);
  }
  return {};
}

Result<void> encrypt_raw_authenticated_stream(Variant variant, Span key, Span tweak, Span iv,
                                              mac::Mac m, std::uint32_t chunk_size,
                                              std::istream& in, std::ostream& out) {
  if (auto v = validate_raw_auth_params(variant, iv, chunk_size); !v) return std::unexpected(v.error());
  auto keys_r = split_raw_key(variant, key);
  if (!keys_r) return std::unexpected(keys_r.error());
  Keys keys = std::move(*keys_r);
  ScopeExit wipe{[&] { wipe_keys(keys); }};  // scrub keys on every exit path
  Threefish tf(variant, keys.enc, tweak);
  std::uint64_t bpc = chunk_size / block_size(variant);

  // Read one chunk ahead so each chunk knows whether it is the last (which is
  // authenticated, defeating truncation) -- same shape as encrypt_password_stream.
  std::vector<std::uint8_t> counter(iv.begin(), iv.end());
  Bytes cur;
  read_up_to(in, cur, chunk_size);
  std::uint64_t idx = 0;
  for (;;) {
    Bytes next;
    read_up_to(in, next, chunk_size);
    bool is_last = next.empty();
    Bytes ct = cur;
    tf.ctr_apply(counter, ct);
    auto tag = mac::tag(m, keys.mac, raw_frame_aad(tweak, iv, idx, is_last, ct));
    std::uint8_t lastb = is_last ? 1 : 0;
    out.write(reinterpret_cast<const char*>(&lastb), 1);
    Bytes lenb;
    put_u32be(lenb, std::uint32_t(ct.size()));
    write_bytes(out, lenb);
    write_bytes(out, ct);
    write_bytes(out, tag);
    if (is_last) break;
    iv_advance(counter, bpc);
    cur = std::move(next);
    ++idx;
  }
  return {};
}

Result<void> decrypt_raw_authenticated_stream(Variant variant, Span key, Span tweak, Span iv,
                                              mac::Mac m, std::uint32_t chunk_size,
                                              std::istream& in, std::ostream& out) {
  if (auto v = validate_raw_auth_params(variant, iv, chunk_size); !v) return std::unexpected(v.error());
  // Bound the chunk size (which bounds every frame allocation) before deriving
  // any key; on decrypt it may be relayed from an untrusted source.
  if (chunk_size > max_chunk_bytes())
    return std::unexpected("chunk size " + std::to_string(chunk_size) +
                           " exceeds the accepted maximum");
  auto keys_r = split_raw_key(variant, key);
  if (!keys_r) return std::unexpected(keys_r.error());
  Keys keys = std::move(*keys_r);
  ScopeExit wipe{[&] { wipe_keys(keys); }};  // scrub keys on every exit path
  Threefish tf(variant, keys.enc, tweak);
  std::uint64_t bpc = chunk_size / block_size(variant);
  std::vector<std::uint8_t> counter(iv.begin(), iv.end());

  std::uint64_t idx = 0;
  for (;;) {
    Bytes is_last_b;
    if (!read_up_to(in, is_last_b, 1)) return std::unexpected("truncated: no final frame before end of input");
    Bytes len_b;
    if (!read_up_to(in, len_b, 4)) return std::unexpected("truncated frame");
    std::uint32_t ct_len = 0;
    for (int i = 0; i < 4; ++i) ct_len = ct_len << 8 | len_b[i];
    if (ct_len > chunk_size) return std::unexpected("frame ct_len exceeds chunk size");
    Bytes ct;
    if (!read_up_to(in, ct, ct_len)) return std::unexpected("truncated frame");
    Bytes tag;
    if (!read_up_to(in, tag, 32)) return std::unexpected("truncated frame");
    bool is_last = is_last_b[0] == 1;
    // Verify before decrypting (which also rejects a wrong key), so no
    // plaintext from an unverified frame is ever written.
    auto expected = mac::tag(m, keys.mac, raw_frame_aad(tweak, iv, idx, is_last, ct));
    if (!ct_eq(expected, tag)) return std::unexpected("authentication failed");
    if (!is_last && ct.size() != chunk_size)
      return std::unexpected("non-final frame is not a full chunk");
    Bytes pt = ct;
    tf.ctr_apply(counter, pt);
    write_bytes(out, pt);
    if (is_last) return {};
    iv_advance(counter, bpc);
    ++idx;
  }
}

// --- in-memory wrappers over the streaming core ---

namespace {
std::istringstream as_stream(Span b) {
  return std::istringstream(std::string(reinterpret_cast<const char*>(b.data()), b.size()),
                            std::ios::binary);
}
Bytes drain(std::ostringstream& oss) {
  std::string s = oss.str();
  return Bytes(s.begin(), s.end());
}
}  // namespace

Bytes encrypt_password_with(const Options& opts, Span salt, Span tweak, Span iv, Span password,
                            Span plaintext) {
  auto in = as_stream(plaintext);
  std::ostringstream oss(std::ios::binary);
  encrypt_password_stream(opts, salt, tweak, iv, password, in, oss);
  return drain(oss);
}

Bytes encrypt_password(const Options& opts, Span tweak, Span password, Span plaintext) {
  Bytes salt(16), iv(block_size(opts.variant));
  random_bytes(salt);
  random_bytes(iv);
  return encrypt_password_with(opts, salt, tweak, iv, password, plaintext);
}

Result<Bytes> decrypt_password_expecting(Span password, std::optional<Span> expect, Span container) {
  auto in = as_stream(container);
  std::ostringstream oss(std::ios::binary);
  // Decrypting is the one entrypoint fed wholly untrusted bytes, and this API reports
  // failure through Result. A backend that throws (OpenSSL's EVP_KDF_derive does, via
  // kdf::derive) would otherwise escape as an uncaught exception and abort the process
  // rather than return an error; fuzz_decrypt found exactly that. Header parameters
  // are validated before any key is derived, so this is the backstop, not the guard.
  try {
    auto r = decrypt_password_stream(password, expect, in, oss);
    if (!r) return std::unexpected(r.error());
  } catch (const std::exception& e) {
    return std::unexpected(std::string("decryption failed: ") + e.what());
  }
  return drain(oss);
}

Result<Bytes> decrypt_password(Span password, Span container) {
  return decrypt_password_expecting(password, std::nullopt, container);
}

Result<Bytes> raw_ctr(Span key, Span tweak, Span iv, Span data) {
  auto in = as_stream(data);
  std::ostringstream oss(std::ios::binary);
  auto r = raw_ctr_stream(key, tweak, iv, in, oss);
  if (!r) return std::unexpected(r.error());
  return drain(oss);
}

Result<Bytes> encrypt_raw_authenticated(Variant variant, Span key, Span tweak, Span iv, mac::Mac m,
                                        std::uint32_t chunk_size, Span plaintext) {
  auto in = as_stream(plaintext);
  std::ostringstream oss(std::ios::binary);
  auto r = encrypt_raw_authenticated_stream(variant, key, tweak, iv, m, chunk_size, in, oss);
  if (!r) return std::unexpected(r.error());
  return drain(oss);
}

Result<Bytes> decrypt_raw_authenticated(Variant variant, Span key, Span tweak, Span iv, mac::Mac m,
                                        std::uint32_t chunk_size, Span data) {
  auto in = as_stream(data);
  std::ostringstream oss(std::ios::binary);
  auto r = decrypt_raw_authenticated_stream(variant, key, tweak, iv, m, chunk_size, in, oss);
  if (!r) return std::unexpected(r.error());
  return drain(oss);
}

Result<ContainerInfo> inspect(Span container) {
  auto pr = format::parse(container);
  if (!pr) return std::unexpected(pr.error());
  const auto& h = pr->header;
  return ContainerInfo{h.version, h.variant, h.kdf,    h.mac,
                       h.chunk_size, h.salt.size(), h.tweak, h.label};
}

}  // namespace dorado::engine
