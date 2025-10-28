#ifndef CORE_CRYPTO_ENGINE_H
#define CORE_CRYPTO_ENGINE_H

#include <string>
#include <vector>

/**
 * CryptoEngine
 *
 * Placeholder for symmetric encryption/decryption.
 * Later will wrap libsodium (XChaCha20-Poly1305).
 *
 * For now it's just a skeleton so code links.
 */
class CryptoEngine {
public:
    CryptoEngine() = default;

    // Encrypt plain text using some key -> cipher_text
    std::vector<unsigned char> encrypt(const std::string &text, const std::vector<unsigned char> &key);
    // Decrypt cipher_text using some key -> plain text
    std::string decrypt(const std::string &cipher, const std::vector<unsigned char> &key);
};

#endif //CORE_CRYPTO_ENGINE_H
