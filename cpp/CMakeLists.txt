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

enable_testing()
add_executable(dorado_test tests/test.cpp)
target_link_libraries(dorado_test PRIVATE dorado)
# Run from the source dir so the committed cross-compat fixtures resolve.
add_test(NAME dorado_test COMMAND dorado_test WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
