#ifndef CORE_STORAGE_STORAGE_BACKEND_H
#define CORE_STORAGE_STORAGE_BACKEND_H

#include <string>
#include <vector>
#include <optional>

/**
 * StorageBackend
 *
 * Abstract interface for vault storage.
 * Later we can implement:
 *  - LocalEncryptedStorage (SQLite/SQLCipher)
 *  - RemoteSyncStorage
 */
class StorageBackend {
public:
    virtual ~StorageBackend() = default;
    virtual bool save(const std::string &id, const std::vector<unsigned char> &data) = 0;
    virtual std::optional<std::vector<unsigned char>> load(const std::string &id) = 0;
};

#endif //CORE_STORAGE_STORAGE_BACKEND_H
