#include <sodium.h>
#include <stdexcept>
#include <sstream>

#include "KeyDerivation.h"

#include "utils/Logger.h"

static constexpr std::size_t ENCORA_DERIVED_KEY_SIZE = 32; // 256-bit key

KdfParams KeyDerivation::defaultParams() {
    KdfParams params;
    // These values correspond to "interactive" or "moderate" security profiles in libsodium terms.
    // We will tune them later for "sensitive data" profiles (higher cost).
    params.opsLimit = crypto_pwhash_OPSLIMIT_MODERATE;
    params.memLimit = crypto_pwhash_MEMLIMIT_MODERATE;

    return params;
}

std::vector<unsigned char> KeyDerivation::derive(const std::string &password, const std::vector<unsigned char> &salt, const KdfParams &params) {
    if (salt.size() < crypto_pwhash_SALTBYTES) {
        throw std::runtime_error("KeyDerivation::derive: salt is too short.");
    }

    if (password.empty()) {
        throw std::runtime_error("KeyDerivation::derive: password is empty. It's not allowed.");
    }

    if (sodium_init() < 0) {
        throw std::runtime_error("KeyDerivation::derive: sodium_init() failed.");
    }

    std::vector<unsigned char> key(ENCORA_DERIVED_KEY_SIZE);

    // crypto_pwhash does Argon2id (we specify ALG_ARGON2ID13).
    // It is memory-hard and slow enough to resist brute-force.
    int r = crypto_pwhash(
            key.data(),
            key.size(),
            password.c_str(),
            password.size(),
            salt.data(),
            params.opsLimit,
            params.memLimit,
            crypto_pwhash_ALG_ARGON2ID13
        );

    if (r != 0) {
        throw std::runtime_error("KeyDerivation::derive: crypto_pwhash() failed (OOM?).");
    }

    {
        std::ostringstream oss;
        oss << "Argon2id KEY is ok. opslimit=" << params.opsLimit
            << " memlimit=" << params.memLimit
            << " size=" << key.size();

        EncoraLogger::Logger::log(EncoraLogger::Level::Debug, oss.str());
    }

    return key;
}
