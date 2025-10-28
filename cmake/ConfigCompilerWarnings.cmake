function(encora_set_common_warnings TARGET_NAME)
    if (MSVC)
        # /W4 = high waning level
        target_compile_options(${TARGET_NAME} PRIVATE /W4 /permissive-)
    else ()
        # -Wall -Wextra -Wpedantic: common strict warning set
        target_compile_options(${TARGET_NAME} PRIVATE
                -Wall
                -Wextra
                -Wpedantic
                -Wconversion
                -Wsign-conversion
                -Wshadow
                -Wnon-virtual-dtor
                -Wold-style-cast
                -Woverloaded-virtual
                -Wdouble-promotion
                -Wformat=2
        )
    endif ()
endfunction()