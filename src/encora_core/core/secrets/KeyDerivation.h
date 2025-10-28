#ifndef CORE_SECRETS_KEY_DERIVATION_H
#define CORE_SECRETS_KEY_DERIVATION_H

#include <vector>
#include <string>

/**
 * KeyDerivation
 *
 * Derives a fixed-size binary key from a user-provided password.
 * Eventually: Argon2id (via libsodium).
 * Currently: placeholder just to enable flow.
 *
 * SECURITY NOTE:
 * This is not secure yet. We will replace this with Argon2id.
 */
class KeyDerivation {
public:
    static std::vector<unsigned char> derive(const std::string &password, const std::vector<unsigned char> &salt);
};

#endif //CORE_SECRETS_KEY_DERIVATION_H
