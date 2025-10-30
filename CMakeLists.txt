cmake_minimum_required(VERSION 3.20)

# Project metadata
project(Encora VERSION 0.1.0 LANGUAGES CXX DESCRIPTION "Encora - local encrypted vault for secrets, passwords, files and notes.")

# Modern C++ data
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Default to Release if not specified
if (NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE  Release CACHE STRING "Build type" FORCE)
endif ()

# Custom CMake modules
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

# Enable stricter warnings early
include(cmake/ConfigCompilerWarnings.cmake)

# Optional/future static analyzers, clang-tidy integration
include(cmake/ConfigStaticAnalysis.cmake OPTIONAL)
# Install libsodium
include(cmake/FindLibsodium.cmake)
# Install nlohmann::json
include(cmake/FindNlohmannJson.cmake)

# Output directories
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# Include directories
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)

# Add subdirectories/subprojects
add_subdirectory(src/encora_core)
add_subdirectory(src/encora_app)
add_subdirectory(src/cli)
add_subdirectory(tests)

# Future rules
message(STATUS "Encora ${PROJECT_VERSION} configured for ${CMAKE_SYSTEM_NAME}")