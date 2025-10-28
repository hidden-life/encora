include(FetchContent)
FetchContent_Declare(
        catch2
        GIT_REPOSITORY https://github.com/catchorg/Catch2.git
        GIT_TAG v3.5.2
)
FetchContent_MakeAvailable(catch2)

add_executable(encora_tests
        test_main.cpp
        core/test_KeyDerivation.cpp
)

target_include_directories(encora_tests PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/..
        ${CMAKE_CURRENT_SOURCE_DIR}/../src/encora_core/core
)

target_link_libraries(encora_tests PRIVATE encora_core Catch2::Catch2WithMain)

encora_set_common_warnings(encora_tests)