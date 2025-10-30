#ifndef CORE_VAULT_METADATA_IO_H
#define CORE_VAULT_METADATA_IO_H

#include "VaultMetadata.h"

/**
 * VaultMetadataIO
 *
 * Responsible for saving and loading vault metadata from disk in JSON format using nlohmann::json.
 *
 * Binary fields (salt, nonce, ciphertext) are Base64-encoded.
 */
class VaultMetadataIO {
public:
    // Load metadata from disk path. Throws on failure.
    static VaultMetadata load(const std::string &path);

    // Save metadata to disk path. Overwrites existing file.
    static void save(const std::string &path, const VaultMetadata &meta);
};

#endif //CORE_VAULT_METADATA_IO_H
