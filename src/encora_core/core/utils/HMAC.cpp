#include <sodium.h>

#include "HMAC.h"

namespace HMAC {
    std::vector<unsigned char> computeSha256(const std::string &data, const std::vector<unsigned char> &key) {
        std::vector<unsigned char> mac(crypto_auth_hmacsha256_BYTES);
        crypto_auth_hmacsha256_state state;
        crypto_auth_hmacsha256_init(&state, key.data(), key.size());
        crypto_auth_hmacsha256_update(&state, reinterpret_cast<const unsigned char *>(data.data()), data.size());
        crypto_auth_hmacsha256_final(&state, mac.data());

        return mac;
    }

    bool verify(const std::string &data, const std::vector<unsigned char> &key, const std::vector<unsigned char> &expected) {
        return sodium_memcmp(
            computeSha256(data, key).data(),
            expected.data(),
            computeSha256(data, key).size()
            ) == 0;
    }
}