# Core library (engine)
include(FetchContent)
# Fetch spdlog
FetchContent_Declare(spdlog
        GIT_REPOSITORY https://github.com/gabime/spdlog.git
        GIT_TAG v1.16.0
)
FetchContent_MakeAvailable(spdlog)

add_library(encora_core STATIC
        core/VaultManager.cpp
        core/CryptoEngine.cpp
        core/secrets/KeyDerivation.cpp
        core/utils/Logger.cpp
        storage/LocalEncryptedStorage.cpp
)

target_include_directories(encora_core PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}/../..
        ${CMAKE_CURRENT_SOURCE_DIR}/core
)

target_link_libraries(encora_core PUBLIC spdlog::spdlog)

# Platform-specific defines
if (WIN32)
    target_compile_definitions(encora_core PRIVATE ENCORA_PLATFORM_WINDOWS)
else ()
    target_compile_definitions(encora_core PRIVATE ENCORA_PLATFORM_UNIX)
endif ()

encora_set_common_warnings(encora_core)

set_target_properties(encora_core PROPERTIES POSITION_INDEPENDENT_CODE ON)