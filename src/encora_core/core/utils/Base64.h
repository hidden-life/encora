#ifndef CORE_UTILS_BASE64_H
#define CORE_UTILS_BASE64_H

#include <string>
#include <vector>

/**
 * Base64 utility for encoding/decoding binary data.
 * Used for storing cryptographic fields (salt, nonce, ciphertext) as strings in vault.meta JSON.
 */
namespace Base64 {
    std::string encode(const std::vector<unsigned char> &data);
    std::vector<unsigned char> decode(const std::string &input);
}

#endif //CORE_UTILS_BASE64_H
