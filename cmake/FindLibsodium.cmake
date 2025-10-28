include(FetchContent)

# Fetch libsodium
FetchContent_Declare(Sodium
        GIT_REPOSITORY https://github.com/robinlinden/libsodium-cmake.git
        GIT_TAG e5b985ad0dd235d8c4307ea3a385b45e76c74c6a
)

set(SODIUM_DISABLE_TESTS ON)
FetchContent_MakeAvailable(Sodium)