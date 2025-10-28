#include "CryptoEngine.h"

std::vector<unsigned char> CryptoEngine::encrypt(const std::string &text, const std::vector<unsigned char> &key) {
    // TEMPORARY FAKE ENCRYPTION
    // just XOR for each byte with key[0] for stub logic
    // (this is NOT secure, it's just to prove pipeline)
    std::vector<unsigned char> result;
    result.reserve(text.size());
    const unsigned char k = key.empty() ? 0xAA : key[0];
    for (const unsigned char c : text) {
        result.push_back(c ^ k);
    }

    return result;
}

std::string CryptoEngine::decrypt(const std::string &cipher, const std::vector<unsigned char> &key) {
    // reverse of encrypt() stub
    const unsigned char k = key.empty() ? 0xAA : key[0];
    std::string result;
    result.reserve(cipher.size());

    for (const unsigned char c : cipher) {
        result.push_back(static_cast<char>(c ^ k));
    }

    return result;
}
