cmake_minimum_required(VERSION 3.20)
project(dorado_cpp LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

add_compile_options(-Wall -Wextra)

# Optional instrumentation. SANITIZE builds the whole library + tests under
# AddressSanitizer + UndefinedBehaviorSanitizer (CI runs this in a second build dir);
# FUZZ builds the libFuzzer decrypt harness (needs Clang). These set global flags, so
# they must come before any target is defined. A normal build leaves both off and the
# shipped library/CLIs keep their usual flags.
option(SANITIZE "Build with AddressSanitizer + UndefinedBehaviorSanitizer" OFF)
option(FUZZ "Build the libFuzzer decrypt harness (requires Clang)" OFF)

if(SANITIZE)
  add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer -g)
  add_link_options(-fsanitize=address,undefined)
endif()

if(FUZZ)
  if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    message(FATAL_ERROR "FUZZ requires Clang (libFuzzer); set -DCMAKE_CXX_COMPILER=clang++")
  endif()
  # Instrument the library for coverage (fuzzer-no-link) plus the sanitizers; the
  # harness target itself links the libFuzzer main with -fsanitize=fuzzer below.
  add_compile_options(-fsanitize=fuzzer-no-link,address,undefined -fno-omit-frame-pointer -g)
  add_link_options(-fsanitize=address,undefined)
endif()

# KDFs (Argon2id/scrypt/PBKDF2) are delegated to OpenSSL's EVP_KDF; OpenSSL >= 3.2
# is required for Argon2. Everything else (cipher, Skein, BLAKE3, SHA-256/HMAC) is
# from scratch.
find_package(OpenSSL 3.2 REQUIRED)

add_library(dorado STATIC
  src/threefish.cpp
  src/skein.cpp
  src/blake3.cpp
  src/sha256.cpp
  src/mac.cpp
  src/kdf.cpp
  src/format.cpp
  src/engine.cpp
)
target_include_directories(dorado PUBLIC include)
target_link_libraries(dorado PUBLIC OpenSSL::Crypto)

add_executable(dorado_cli src/cli_dorado.cpp)
set_target_properties(dorado_cli PROPERTIES OUTPUT_NAME dorado)
target_link_libraries(dorado_cli PRIVATE dorado)

add_executable(gyotaku_cli src/cli_gyotaku.cpp)
set_target_properties(gyotaku_cli PROPERTIES OUTPUT_NAME gyotaku)
target_link_libraries(gyotaku_cli PRIVATE dorado)

enable_testing()
add_executable(dorado_test tests/test.cpp)
target_link_libraries(dorado_test PRIVATE dorado)
# Run from the source dir so the committed cross-compat fixtures resolve.
add_test(NAME dorado_test COMMAND dorado_test WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})

if(FUZZ)
  add_executable(dorado_fuzz fuzz/fuzz_decrypt.cpp)
  target_link_libraries(dorado_fuzz PRIVATE dorado)
  target_link_options(dorado_fuzz PRIVATE -fsanitize=fuzzer)
endif()
