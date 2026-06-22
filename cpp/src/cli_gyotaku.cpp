// gyotaku: Skein-512 file hashing (like sha256sum but Skein). Streams files in
// constant memory via the incremental hasher. --bits, --tag, -c/--check.
#include <cctype>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

#include "dorado/skein.hpp"

namespace {

using Bytes = std::vector<std::uint8_t>;

const char* kVersion = "gyotaku 0.1.0";
const char* kUsage =
    "Skein-512 file hashing, a fish-print fingerprint. Educational, unaudited.\n\n"
    "Usage: gyotaku [OPTIONS] [FILES]...\n\n"
    "  --bits <BITS>  Output length in bits (a multiple of 8) [default: 256]\n"
    "  -c, --check    Verify digests read from the FILES (like `sha256sum -c`)\n"
    "      --tag      BSD-style tagged output: \"SKEIN-512 (file) = digest\"\n"
    "  -h, --help     Print help\n"
    "  -V, --version  Print version\n";

std::string to_hex(const Bytes& b) {
  static const char* d = "0123456789abcdef";
  std::string s;
  for (std::uint8_t x : b) {
    s += d[x >> 4];
    s += d[x & 0xf];
  }
  return s;
}

// Stream-hash an istream in constant memory.
Bytes hash_stream(std::size_t out_bytes, std::istream& in) {
  dorado::skein::Hasher h(out_bytes);
  std::vector<char> buf(65536);
  while (in) {
    in.read(buf.data(), std::streamsize(buf.size()));
    std::streamsize n = in.gcount();
    if (n > 0)
      h.update(std::span<const std::uint8_t>(reinterpret_cast<std::uint8_t*>(buf.data()),
                                             std::size_t(n)));
  }
  return h.finalize();
}

Bytes hash_file(std::size_t out_bytes, const std::string& path) {
  std::ifstream f(path, std::ios::binary);
  return hash_stream(out_bytes, f);
}

int run_check(const std::vector<std::string>& files) {
  int bad = 0;
  for (const auto& list : files) {
    std::ifstream lf(list);
    std::string line;
    while (std::getline(lf, line)) {
      // "digest  file" or "SKEIN-512 (file) = digest"
      std::string digest, file;
      if (line.rfind("SKEIN-512 (", 0) == 0) {
        auto close = line.find(')');
        if (close == std::string::npos) continue;
        file = line.substr(11, close - 11);
        auto eq = line.find("= ", close);
        if (eq == std::string::npos) continue;
        digest = line.substr(eq + 2);
      } else {
        auto sp = line.find(' ');
        if (sp == std::string::npos) continue;
        digest = line.substr(0, sp);
        file = line.substr(line.find_first_not_of(' ', sp));
      }
      if (digest.empty() || file.empty()) continue;
      std::string actual = to_hex(hash_file(digest.size() / 2, file));
      if (actual == digest) {
        std::cout << file << ": OK\n";
      } else {
        std::cout << file << ": FAILED\n";
        ++bad;
      }
    }
  }
  return bad == 0 ? 0 : 1;
}

}  // namespace

int main(int argc, char** argv) {
  std::size_t bits = 256;
  bool check = false, tag = false;
  std::vector<std::string> files;
  for (int i = 1; i < argc; ++i) {
    std::string a = argv[i];
    if (a == "-h" || a == "--help") { std::cout << kUsage; return 0; }
    if (a == "-V" || a == "--version") { std::cout << kVersion << "\n"; return 0; }
    if (a == "-c" || a == "--check") { check = true; }
    else if (a == "--tag") { tag = true; }
    else if (a == "--bits") {
      if (++i >= argc) { std::cerr << "gyotaku: --bits needs a value\n"; return 1; }
      bits = std::stoul(argv[i]);
    } else if (!a.empty() && a[0] == '-') {
      std::cerr << "gyotaku: unknown option " << a << "\n";
      return 1;
    } else {
      files.push_back(a);
    }
  }
  if (bits == 0 || bits % 8 != 0) { std::cerr << "gyotaku: --bits must be a positive multiple of 8\n"; return 1; }

  if (check) return run_check(files);

  std::size_t out_bytes = bits / 8;
  if (files.empty()) {
    std::cout << to_hex(hash_stream(out_bytes, std::cin)) << "\n";
  } else {
    for (const auto& f : files) {
      std::string d = to_hex(hash_file(out_bytes, f));
      if (tag)
        std::cout << "SKEIN-512 (" << f << ") = " << d << "\n";
      else
        std::cout << d << "  " << f << "\n";
    }
  }
  return 0;
}
