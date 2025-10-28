#ifndef CORE_PLATFORMS_PLATFORM_PATHS_H
#define CORE_PLATFORMS_PLATFORM_PATHS_H

#include <string>

/**
 * PlatformPaths
 *
 * Will resolve platform-specific directories, e.g.:
 *  - %APPDATA%\Encora on Windows
 *  - ~/.local/share/encora on Linux
 *
 *  Currently hust returns "./data"
 */
struct PlatformPaths {
    static std::string dataDir() {
        return "data";
    }
};

#endif //CORE_PLATFORMS_PLATFORM_PATHS_H
