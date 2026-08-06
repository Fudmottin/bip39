cmake_minimum_required(VERSION 3.20)

project(bip39 LANGUAGES CXX)

# Use Release unless the caller explicitly selects another build type.
# CMAKE_CONFIGURATION_TYPES protects multi-configuration generators.
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
   set(
      CMAKE_BUILD_TYPE
      Release
      CACHE STRING "Build type: Release or Debug"
      FORCE
   )
endif()

find_package(OpenSSL REQUIRED COMPONENTS Crypto)
find_package(Boost 1.90 CONFIG REQUIRED COMPONENTS program_options)

include(CTest)

add_library(
   bip39_core
   STATIC
   src/bip39.cpp
   src/english_words.cpp
)

target_compile_features(
   bip39_core
   PUBLIC
      cxx_std_20
)

target_include_directories(
   bip39_core
   PUBLIC
      "${CMAKE_CURRENT_SOURCE_DIR}/src"
)

target_link_libraries(
   bip39_core
   PRIVATE
      OpenSSL::Crypto
)

add_executable(
   seeds
   src/seeds.cpp
)

target_link_libraries(
   seeds
   PRIVATE
      bip39_core
      Boost::program_options
)

if(BUILD_TESTING)
   add_subdirectory(tests)
endif()

