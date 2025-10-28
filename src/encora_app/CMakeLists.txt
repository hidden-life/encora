# GUI application using Qt6 Widgets
find_package(Qt6 REQUIRED COMPONENTS Core Gui Widgets)

qt_standard_project_setup()

set(APP_SOURCES
        main.cpp

        ApplicationController.cpp

        ui/MainWindow.cpp
)

set(APP_RESOURCES resources/resources.qrc)

qt_add_executable(encora ${APP_SOURCES} ${APP_RESOURCES})

target_include_directories(encora PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

# Link with encora_core and Qt
target_link_libraries(encora PRIVATE
        encora_core

        Qt${QT_VERSION_MAJOR}::Core
        Qt${QT_VERSION_MAJOR}::Gui
        Qt${QT_VERSION_MAJOR}::Widgets
)

encora_set_common_warnings(encora)

if (CMAKE_BUILD_TYPE STREQUAL "Debug")
    set_target_properties(encora PROPERTIES WIN32_EXECUTABLE FALSE)
else ()
    set_target_properties(encora PROPERTIES
            WIN32_EXECUTABLE TRUE
            MACOSX_BUNDLE TRUE
    )
endif ()

install(TARGETS encora)