#ifndef CORE_SECRETS_KEY_DERIVATION_H
#define CORE_SECRETS_KEY_DERIVATION_H

#include <vector>
#include <string>
#include <cstdint>

/**
 * KeyDerivation
 *
 * Derives a fixed-size binary key from a user-provided password.
 * Eventually: Argon2id (via libsodium).
 *
 * SECURITY NOTE:
 *  - This is the *core* of Encora's password-based security model.
 *  - The derived key is NOT stored on disk in plaintext.
 *  - The salt is stored (salt is not secret, it's needed to reproduce the same key), but must be unique per vault.
 *
 *  The output key (derived key) will later be used to decrypt the vault master key (VMK).
 *
 *  Usage:
 *      1. Load salt from vault metadata (16 or 32 random bytes generated at vault creation).
 *      2 .Call derive(password, salt, params)
 *      3. Use returned key as AES/XChaCha20 key to unwrap VMK.
 */

struct KdfParams {
    // Memory cost for Argon2id (in bytes).
    // Libsodium uses "opsLimit" and "memLimit" instead of direct Argon2 params.
    // We'll wrap them here for clarity.
    std::uint64_t opsLimit; // how computationally expensive (iterations)
    std::size_t memLimit; // how memory-expensive (bytes)
};

class KeyDerivation {
public:
    // Derive a 32-byte key from a password and salt using Argon2id.
    // Salt must be cryptographically random, same salt must be reused
    // to reproduce the same derived key for the same vault.
    //
    // Returns: vector<unsigned char> of length 32.
    static std::vector<unsigned char> derive(const std::string &password, const std::vector<unsigned char> &salt, const KdfParams &params);
    // Helper to generate recommended/default parameters.
    static KdfParams defaultParams();
};

#endif //CORE_SECRETS_KEY_DERIVATION_H
