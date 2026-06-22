// dorado: password/raw-key encryption CLI. Password mode derives a key and writes
// an authenticated container; raw-key mode is bare CTR. `inspect` prints the
// non-secret header. Streams over file/std handles in constant memory.
#include <cctype>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <iterator>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <variant>
#include <vector>

#include "dorado/engine.hpp"

namespace {

using Bytes = std::vector<std::uint8_t>;
using dorado::engine::Options;

const char* kUsage =
    "dorado - Threefish encryption with a password container or a raw key.\n\n"
    "Usage:\n"
    "  dorado encrypt --password-stdin --in <f> --out <f> [--kdf K --mac M --variant V\n"
    "                 --chunk-kib N --label L --tweak HEX + KDF cost flags]\n"
    "  dorado encrypt --key HEX|--key-file F --iv HEX [--tweak HEX] --in <f> --out <f>\n"
    "  dorado decrypt --password-stdin [--expect-label L] --in <f> --out <f>\n"
    "  dorado decrypt --key HEX|--key-file F --iv HEX [--tweak HEX] --in <f> --out <f>\n"
    "  dorado inspect --in <f>\n\n"
    "  --kdf argon2id|scrypt|pbkdf2   --mac skein|hmac-sha256|blake3   --variant 256|512|1024\n"
    "  cost: --argon2-mem-mib --argon2-time --argon2-par --scrypt-logn --scrypt-r --scrypt-p --pbkdf2-rounds\n"
    "  -h, --help    -V, --version\n";

int die(const std::string& m) {
  std::cerr << "dorado: " << m << "\n";
  return 1;
}

Bytes to_bytes(const std::string& s) { return Bytes(s.begin(), s.end()); }

std::optional<Bytes> parse_hex(const std::string& s) {
  std::string clean;
  for (char c : s)
    if (!std::isspace(static_cast<unsigned char>(c))) clean += c;
  if (clean.size() % 2) return std::nullopt;
  auto hv = [](char c) -> int {
    if (c >= '0' && c <= '9') return c - '0';
    c |= 0x20;
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
  };
  Bytes out;
  for (std::size_t i = 0; i < clean.size(); i += 2) {
    int hi = hv(clean[i]), lo = hv(clean[i + 1]);
    if (hi < 0 || lo < 0) return std::nullopt;
    out.push_back(std::uint8_t(hi << 4 | lo));
  }
  return out;
}

std::string read_all(std::istream& in) {
  return std::string(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
}

const std::set<std::string> kValueFlags = {
    "--key", "--key-file", "--iv", "--tweak", "--variant", "--kdf", "--mac", "--chunk-kib",
    "--label", "--expect-label", "--in", "--out", "--argon2-mem-mib", "--argon2-time",
    "--argon2-par", "--scrypt-logn", "--scrypt-r", "--scrypt-p", "--pbkdf2-rounds"};

struct Flags {
  std::map<std::string, std::string> v;
  std::set<std::string> b;
  std::optional<std::string> get(const std::string& k) const {
    auto it = v.find(k);
    return it == v.end() ? std::nullopt : std::optional<std::string>(it->second);
  }
  bool has(const std::string& k) const { return b.count(k) > 0; }
  std::string get_or(const std::string& k, const std::string& d) const {
    auto g = get(k);
    return g ? *g : d;
  }
  long get_int(const std::string& k, long d) const {
    auto g = get(k);
    return g ? std::stol(*g) : d;
  }
};

std::optional<Flags> parse_flags(int argc, char** argv, int start) {
  Flags f;
  for (int i = start; i < argc; ++i) {
    std::string a = argv[i];
    if (kValueFlags.count(a)) {
      if (++i >= argc) {
        std::cerr << "dorado: " << a << " needs a value\n";
        return std::nullopt;
      }
      f.v[a] = argv[i];
    } else if (!a.empty() && a[0] == '-') {
      f.b.insert(a);
    } else {
      std::cerr << "dorado: unexpected argument " << a << "\n";
      return std::nullopt;
    }
  }
  return f;
}

bool password_mode(const Flags& f) { return f.has("--password-stdin") || f.has("--password"); }

std::optional<Bytes> parse_tweak(const Flags& f) {
  auto t = parse_hex(f.get_or("--tweak", std::string(32, '0')));
  if (!t || t->size() != 16) {
    std::cerr << "dorado: --tweak must be 16 bytes of hex\n";
    return std::nullopt;
  }
  return t;
}

std::optional<Options> build_options(const Flags& f) {
  Options o;
  std::string var = f.get_or("--variant", "256");
  if (var == "256") o.variant = dorado::Variant::TF256;
  else if (var == "512") o.variant = dorado::Variant::TF512;
  else if (var == "1024") o.variant = dorado::Variant::TF1024;
  else { std::cerr << "dorado: unknown variant " << var << "\n"; return std::nullopt; }

  std::string m = f.get_or("--mac", "skein");
  if (m == "skein") o.mac = dorado::mac::Mac::Skein512;
  else if (m == "hmac-sha256") o.mac = dorado::mac::Mac::HmacSha256;
  else if (m == "blake3") o.mac = dorado::mac::Mac::Blake3Keyed;
  else { std::cerr << "dorado: unknown mac " << m << "\n"; return std::nullopt; }

  std::string k = f.get_or("--kdf", "argon2id");
  if (k == "argon2id")
    o.kdf = dorado::kdf::Argon2id{std::uint32_t(f.get_int("--argon2-mem-mib", 64)) * 1024,
                                 std::uint32_t(f.get_int("--argon2-time", 3)),
                                 std::uint32_t(f.get_int("--argon2-par", 1))};
  else if (k == "scrypt")
    o.kdf = dorado::kdf::Scrypt{std::uint8_t(f.get_int("--scrypt-logn", 15)),
                               std::uint32_t(f.get_int("--scrypt-r", 8)),
                               std::uint32_t(f.get_int("--scrypt-p", 1))};
  else if (k == "pbkdf2")
    o.kdf = dorado::kdf::Pbkdf2{std::uint32_t(f.get_int("--pbkdf2-rounds", 600000))};
  else { std::cerr << "dorado: unknown kdf " << k << "\n"; return std::nullopt; }

  o.chunk_size = std::uint32_t(f.get_int("--chunk-kib", 64)) * 1024;
  if (auto l = f.get("--label")) o.label = to_bytes(*l);
  return o;
}

std::optional<Bytes> resolve_key(const Flags& f) {
  if (auto h = f.get("--key")) return parse_hex(*h);
  if (auto p = f.get("--key-file")) {
    std::ifstream kf(*p);
    if (!kf) { std::cerr << "dorado: cannot open " << *p << "\n"; return std::nullopt; }
    return parse_hex(read_all(kf));
  }
  std::cerr << "dorado: raw-key mode needs --key or --key-file\n";
  return std::nullopt;
}

int run_encrypt(const Flags& f) {
  auto tweak = parse_tweak(f);
  if (!tweak) return 1;
  if (password_mode(f)) {
    auto in_path = f.get("--in");
    if (!in_path) return die("password mode needs --in (stdin carries the password)");
    std::ifstream in(*in_path, std::ios::binary);
    if (!in) return die("cannot open " + *in_path);
    auto opts = build_options(f);
    if (!opts) return 1;
    std::string pw = read_all(std::cin);
    if (!pw.empty() && pw.back() == '\n') pw.pop_back();
    Bytes salt(16), iv(block_size(opts->variant));
    dorado::engine::random_bytes(salt);
    dorado::engine::random_bytes(iv);
    std::ofstream fout;
    std::ostream* out = &std::cout;
    if (auto p = f.get("--out")) { fout.open(*p, std::ios::binary); if (!fout) return die("cannot open " + *p); out = &fout; }
    dorado::engine::encrypt_password_stream(*opts, salt, *tweak, iv, to_bytes(pw), in, *out);
    return 0;
  }
  auto key = resolve_key(f);
  if (!key) return 1;
  auto iv_hex = f.get("--iv");
  if (!iv_hex) return die("raw-key mode needs --iv");
  auto iv = parse_hex(*iv_hex);
  if (!iv) return die("invalid --iv hex");
  std::ifstream fin;
  std::istream* in = &std::cin;
  if (auto p = f.get("--in")) { fin.open(*p, std::ios::binary); if (!fin) return die("cannot open " + *p); in = &fin; }
  std::ofstream fout;
  std::ostream* out = &std::cout;
  if (auto p = f.get("--out")) { fout.open(*p, std::ios::binary); if (!fout) return die("cannot open " + *p); out = &fout; }
  auto r = dorado::engine::raw_ctr_stream(*key, *tweak, *iv, *in, *out);
  if (!r) return die(r.error());
  return 0;
}

int run_decrypt(const Flags& f) {
  if (password_mode(f)) {
    auto in_path = f.get("--in");
    if (!in_path) return die("password mode needs --in (stdin carries the password)");
    std::ifstream in(*in_path, std::ios::binary);
    if (!in) return die("cannot open " + *in_path);
    std::string pw = read_all(std::cin);
    if (!pw.empty() && pw.back() == '\n') pw.pop_back();
    Bytes pwb = to_bytes(pw);
    std::ofstream fout;
    std::ostream* out = &std::cout;
    if (auto p = f.get("--out")) { fout.open(*p, std::ios::binary); if (!fout) return die("cannot open " + *p); out = &fout; }
    std::optional<Bytes> label;
    std::optional<dorado::engine::Span> expect;
    if (auto l = f.get("--expect-label")) { label = to_bytes(*l); expect = *label; }
    auto r = dorado::engine::decrypt_password_stream(pwb, expect, in, *out);
    if (!r) return die(r.error());
    return 0;
  }
  auto key = resolve_key(f);
  if (!key) return 1;
  auto tweak = parse_tweak(f);
  if (!tweak) return 1;
  auto iv_hex = f.get("--iv");
  if (!iv_hex) return die("raw-key mode needs --iv");
  auto iv = parse_hex(*iv_hex);
  if (!iv) return die("invalid --iv hex");
  std::ifstream fin;
  std::istream* in = &std::cin;
  if (auto p = f.get("--in")) { fin.open(*p, std::ios::binary); if (!fin) return die("cannot open " + *p); in = &fin; }
  std::ofstream fout;
  std::ostream* out = &std::cout;
  if (auto p = f.get("--out")) { fout.open(*p, std::ios::binary); if (!fout) return die("cannot open " + *p); out = &fout; }
  auto r = dorado::engine::raw_ctr_stream(*key, *tweak, *iv, *in, *out);
  if (!r) return die(r.error());
  return 0;
}

std::string hex_of(const Bytes& b) {
  static const char* d = "0123456789abcdef";
  std::string s;
  for (std::uint8_t x : b) { s += d[x >> 4]; s += d[x & 0xf]; }
  return s;
}

int run_inspect(const Flags& f) {
  Bytes data;
  if (auto p = f.get("--in")) {
    std::ifstream fin(*p, std::ios::binary);
    if (!fin) return die("cannot open " + *p);
    std::string s = read_all(fin);
    data = Bytes(s.begin(), s.end());
  } else {
    std::string s = read_all(std::cin);
    data = Bytes(s.begin(), s.end());
  }
  auto info = dorado::engine::inspect(data);
  if (!info) return die(info.error());

  const char* variant = info->variant == dorado::Variant::TF256   ? "Threefish-256"
                        : info->variant == dorado::Variant::TF512  ? "Threefish-512"
                                                                   : "Threefish-1024";
  const char* mac = info->mac == dorado::mac::Mac::Skein512      ? "Skein-512"
                    : info->mac == dorado::mac::Mac::HmacSha256  ? "HMAC-SHA256"
                                                                 : "BLAKE3 (keyed)";
  std::string kdf = std::visit(
      [](const auto& k) -> std::string {
        using T = std::decay_t<decltype(k)>;
        if constexpr (std::is_same_v<T, dorado::kdf::Argon2id>)
          return "Argon2id (m=" + std::to_string(k.m_cost) + " KiB, t=" + std::to_string(k.t_cost) +
                 ", p=" + std::to_string(k.p_cost) + ")";
        else if constexpr (std::is_same_v<T, dorado::kdf::Scrypt>)
          return "scrypt (log2(N)=" + std::to_string(k.log_n) + ", r=" + std::to_string(k.r) +
                 ", p=" + std::to_string(k.p) + ")";
        else
          return "PBKDF2-HMAC-SHA256 (rounds " + std::to_string(k.rounds) + ")";
      },
      info->kdf);
  std::string label = info->label.empty() ? "(none)" : std::string(info->label.begin(), info->label.end());

  std::cout << "format:   dorado password container (DRDO v" << int(info->version) << ")\n"
            << "variant:  " << variant << "\n"
            << "kdf:      " << kdf << "\n"
            << "mac:      " << mac << "\n"
            << "chunk:    " << info->chunk_size << " bytes\n"
            << "salt:     " << info->salt_len << " bytes\n"
            << "tweak:    " << hex_of(info->tweak) << "\n"
            << "label:    " << label << "\n";
  return 0;
}

}  // namespace

int main(int argc, char** argv) {
  for (int i = 1; i < argc; ++i) {
    std::string a = argv[i];
    if (a == "-h" || a == "--help") { std::cout << kUsage; return 0; }
    if (a == "-V" || a == "--version") { std::cout << "dorado 0.1.0\n"; return 0; }
  }
  if (argc < 2) return die(std::string("missing command\n\n") + kUsage);
  std::string cmd = argv[1];
  auto f = parse_flags(argc, argv, 2);
  if (!f) return 1;
  if (cmd == "encrypt") return run_encrypt(*f);
  if (cmd == "decrypt") return run_decrypt(*f);
  if (cmd == "inspect") return run_inspect(*f);
  return die("unknown command '" + cmd + "'");
}
