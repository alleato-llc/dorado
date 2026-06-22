#include "dorado/engine.hpp"

#include <openssl/rand.h>

#include <algorithm>
#include <array>
#include <sstream>
#include <stdexcept>
#include <utility>

#include "dorado/format.hpp"
#include "internal.hpp"

namespace dorado::engine {
namespace {

constexpr std::array<std::uint8_t, 8> kDomain = {'D', 'R', 'D', 'O', 'c', 'h', 'n', 'k'};

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
  auto r = decrypt_password_stream(password, expect, in, oss);
  if (!r) return std::unexpected(r.error());
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

Result<ContainerInfo> inspect(Span container) {
  auto pr = format::parse(container);
  if (!pr) return std::unexpected(pr.error());
  const auto& h = pr->header;
  return ContainerInfo{h.version, h.variant, h.kdf,    h.mac,
                       h.chunk_size, h.salt.size(), h.tweak, h.label};
}

}  // namespace dorado::engine
