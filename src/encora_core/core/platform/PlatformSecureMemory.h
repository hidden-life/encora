#ifndef CORE_PLATFORM_PLATFORM_SECURE_MEMORY_H
#define CORE_PLATFORM_PLATFORM_SECURE_MEMORY_H

#include <cstddef>

/**
 * PlatformSecureMemory
 *
 * Stub for locking memory pages to prevent swapping.
 */
struct PlatformSecureMemory {
    static bool lock(void*, std::size_t) { return true; }
    static void unlock(void*, std::size_t) {}
};

#endif //CORE_PLATFORM_PLATFORM_SECURE_MEMORY_H
