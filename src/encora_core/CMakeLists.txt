# Core library (engine)
include(FetchContent)
# Fetch spdlog
FetchContent_Declare(spdlog
        GIT_REPOSITORY https://github.com/gabime/spdlog.git
        GIT_TAG v1.16.0
)
FetchContent_MakeAvailable(spdlog)

set(SOURCES
        core/VaultManager.cpp
        core/CryptoEngine.cpp
        core/secrets/KeyDerivation.cpp
        core/secrets/KeyWrap.cpp
        core/utils/Logger.cpp
        core/utils/Base64.cpp
        storage/LocalEncryptedStorage.cpp

        VaultMetadataIO.cpp
)

set(HEADERS
        core/VaultManager.h
        core/VaultMetadata.h
        core/CryptoEngine.h
        core/secrets/KeyDerivation.h
        core/secrets/KeyWrap.h
        core/secrets/SecureWiper.h
        core/utils/Logger.h
        core/utils/Version.h
        core/utils/Base64.h
        storage/LocalEncryptedStorage.h
        storage/StorageBackend.h
        storage/StorageError.h

        VaultMetadataIO.h
)

add_library(encora_core STATIC ${SOURCES} ${HEADERS})

target_include_directories(encora_core PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}/../..
        ${CMAKE_CURRENT_SOURCE_DIR}/core
)

target_link_libraries(encora_core PUBLIC
        spdlog::spdlog
        sodium
        nlohmann_json::nlohmann_json
)

# Platform-specific defines
if (WIN32)
    target_compile_definitions(encora_core PRIVATE ENCORA_PLATFORM_WINDOWS)
else ()
    target_compile_definitions(encora_core PRIVATE ENCORA_PLATFORM_UNIX)
endif ()

encora_set_common_warnings(encora_core)

set_target_properties(encora_core PROPERTIES POSITION_INDEPENDENT_CODE ON)