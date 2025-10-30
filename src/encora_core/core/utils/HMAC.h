#ifndef CORE_UTILS_HMAC_H
#define CORE_UTILS_HMAC_H

#include <string>
#include <vector>

namespace HMAC {
    /**
     * Computes HMAC-SHA256 of input data using the given key.
     * Returns raw 32-byte digest.
     */
    std::vector<unsigned char> computeSha256(const std::string &data, const std::vector<unsigned char> &key);

    /**
     * Verifies that provided HMAC equals computed HMAC.
     */
    bool verify(const std::string &data, const std::vector<unsigned char> &key, const std::vector<unsigned char> &expected);
}

#endif //CORE_UTILS_HMAC_H
