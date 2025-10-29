#ifndef CORE_SECRETS_KEY_WRAP_H
#define CORE_SECRETS_KEY_WRAP_H

#include <vector>
#include <string>

/**
 * KeyWrap
 *
 * This module "wraps" (encrypts + authenticates) the Vault Master Key (VMK) using a key derived from the user's master password.
 *
 * We use XChaCha20-Poly1305 (AEAD) from libsodium.
 *
 * wrap():
 *      input: plainText VMK (32 bytes), derivedKey (32 bytes)
 *      output: nonce (24 bytes) + cipherText (VMK + MAC)
 *
 * unwrap():
 *      input: nonce + cipherText + derivedKey
 *      output: plainText VMK
 */
struct WrappedKey {
    std::vector<unsigned char> nonce; // 24 bytes
    std::vector<unsigned char> cipherText; // encrypted VMK + MAC
};

class KeyWrap {
public:
    static WrappedKey wrap(const std::vector<unsigned char> &vmk, const std::vector<unsigned char> &derived);
    static std::vector<unsigned char> unwrap(const WrappedKey &wrapped, const std::vector<unsigned char> &derived);
};

#endif //CORE_SECRETS_KEY_WRAP_H
