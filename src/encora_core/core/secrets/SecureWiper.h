#ifndef CORE_SECRETS_SECURE_VIPER_H
#define CORE_SECRETS_SECURE_VIPER_H

#include <cstddef>
#include <cstring>

/**
 * SecureWiper
 *
 * Helper for wiping sensitive memory (keys, decrypted data).
 * We'll later improve this using OS-specific secure_zero_memory.
 */
struct SecureWiper {
    static void wipe(void *ptr, std::size_t len) {
        if (!ptr || len == 0) return;
        // volatile pointer to avoid optimization-out
        volatile unsigned char *p = reinterpret_cast<volatile unsigned char*>(ptr);
        while (len--) *p++ = 0;
    }
};

#endif //CORE_SECRETS_SECURE_VIPER_H
