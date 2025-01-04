cmake_minimum_required(VERSION 3.15)
project(SeedPicker LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Set the default build type to Release with optimization
if (NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type: Release or Debug" FORCE)
endif()

# Add flags for Release and Debug
set(CMAKE_CXX_FLAGS_RELEASE "-O3 -DNDEBUG")
set(CMAKE_CXX_FLAGS_DEBUG "-g")

add_executable(seeds src/seeds.cpp)

