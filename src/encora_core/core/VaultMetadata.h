#ifndef CORE_VAULT_METADATA_H
#define CORE_VAULT_METADATA_H

#include <cstdint>
#include <string>
#include <vector>

/**
 * VaultMetadata
 *
 * Represents the vault metadata loaded from / written to disk.
 * This does NOT contain plaintext keys.
 *
 * Fields:
 *      - version: format version
 *      - kdf params: opsLimit, memLimit, salt
 *      - wrapped VMK: nonce + cipherText
 *
 * The VMK itself is never stored here in plaintext.
 */
struct VaultMetadata {
    uint32_t version = 1;

    std::uint64_t kdfOpsLimit = 0;
    std::uint64_t kdfMemLimit = 0;
    std::vector<unsigned char> kdfSalt; // length >= crypto_pwhash_SALTBYTES

    std::vector<unsigned char> wrappedNonce; // AEAD nonce
    std::vector<unsigned char> wrappedCipherText; // AEAD ciphertext+MAC
};

#endif //CORE_VAULT_METADATA_H
