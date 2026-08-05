cmake_minimum_required(VERSION 3.20)

project(seeds LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Use Release unless the caller explicitly selects another build type.
if(NOT CMAKE_BUILD_TYPE)
   set(
      CMAKE_BUILD_TYPE
      Release
      CACHE STRING "Build type: Release or Debug"
      FORCE
   )
endif()

# BIP-39 requires cryptographically secure randomness and SHA-256.
# Only OpenSSL's Crypto library is needed; TLS is not used by this program.
find_package(OpenSSL REQUIRED COMPONENTS Crypto)

# Command-line argument processing.
find_package(Boost 1.90 CONFIG REQUIRED COMPONENTS program_options)

add_executable(
   seeds
   src/seeds.cpp
   src/english_words.cpp
)

target_link_libraries(
   seeds
   PRIVATE
      OpenSSL::Crypto
      Boost::program_options
)

