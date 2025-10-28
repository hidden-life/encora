#ifndef CORE_STORAGE_LOCAL_ENCRYPTED_STORAGE_H
#define CORE_STORAGE_LOCAL_ENCRYPTED_STORAGE_H

#include <unordered_map>
#include "StorageBackend.h"

/**
 * LocalEncryptedStorage
 *
 * MVP mock: stores encrypted blobs in memory (std::unordered_map).
 * Later this becomes on-disk, encrypted SQLite.
 */
class LocalEncryptedStorage : public StorageBackend {
public:
    std::optional<std::vector<unsigned char>> load(const std::string &id) override;
    bool save(const std::string &id, const std::vector<unsigned char> &data) override;

private:
    std::unordered_map<std::string, std::vector<unsigned char>> m_memory;
};

#endif //CORE_STORAGE_LOCAL_ENCRYPTED_STORAGE_H
