add_executable(encora_cli
        CLI.cpp
        CLIOptions.cpp
)

target_include_directories(encora_cli PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}/../encora_core/core
)

target_link_libraries(encora_cli PRIVATE encora_core)

encora_set_common_warnings(encora_cli)