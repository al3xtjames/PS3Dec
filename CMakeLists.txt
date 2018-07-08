cmake_minimum_required(VERSION 3.10)
project(PS3Dec LANGUAGES C)

# Default to Release builds
if (NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE "Release")
    message(STATUS "No build type selected, defaulting to a Release build")
endif()

# Set C standard requirements
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

# Avoid deprecated CMake syntax
set(CMAKE_WARN_DEPRECATED ON)

# Add external libraries
add_subdirectory(external)

# Add project files
add_subdirectory(src)
