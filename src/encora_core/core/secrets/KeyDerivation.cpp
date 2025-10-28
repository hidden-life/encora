#include "KeyDerivation.h"

std::vector<unsigned char> KeyDerivation::derive(const std::string &password, const std::vector<unsigned char> &salt) {
    // TEMPORARY / INSECURE
    // - produce a 32-byte "key"
    // - copy password bytes into it
    std::vector<unsigned char> key(32, 0);

    for (size_t i = 0; i < key.size() && i < password.size(); ++i) {
        key[i] = static_cast<unsigned char>(password[i]);
    }

    (void)salt; // unused for now, will be used with Argon2id later

    return key;
}
