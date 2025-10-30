add_executable(encora_cli
        main_cli.cpp

        CLIOptions.cpp
        CLIOptions.h
)

target_include_directories(encora_cli PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}/../encora_core/core
)

target_link_libraries(encora_cli PRIVATE encora_core)

encora_set_common_warnings(encora_cli)

set_target_properties(encora_cli PROPERTIES WIN32_EXECUTABLE FALSE)