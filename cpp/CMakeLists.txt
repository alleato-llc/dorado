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

# The from-scratch primitives and (later) the construction. KDFs will be
# delegated to OpenSSL; SHA-256/HMAC and the rest are from scratch.
add_library(dorado STATIC
  src/threefish.cpp
)
target_include_directories(dorado PUBLIC include)

enable_testing()
add_executable(dorado_test tests/test.cpp)
target_link_libraries(dorado_test PRIVATE dorado)
add_test(NAME dorado_test COMMAND dorado_test)
