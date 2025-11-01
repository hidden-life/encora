#ifndef CORE_STORAGE_ENCRYPTED_VAULT_STORAGE_H
#define CORE_STORAGE_ENCRYPTED_VAULT_STORAGE_H

#include <string>
#include <vector>

class EncryptedVaultStorage {
public:
    explicit EncryptedVaultStorage(const std::vector<unsigned char> &vmk);
    // Add new record
    bool addRecord(const std::string &name, const std::string &type, std::vector<unsigned char> &data);
    // Load record by name
    std::vector<unsigned char> loadRecord(const std::string &name);
    // List of all records
    [[nodiscard]]
    std::vector<std::string> list() const;
    // Remove record
    bool remove(const std::string &name);

private:
    std::vector<unsigned char> m_vmk;
    [[nodiscard]]
    std::string path(const std::string &id) const;
    void ensureStorageDir() const;
    // derive per-record key using VMK + record salt (HMAC-SHA256)
    static std::vector<unsigned char> deriveRecordKey(const std::vector<unsigned char> &vmk, const std::vector<unsigned char> &salt);
    static std::string base64Encode(const std::vector<unsigned char> &data);
    static std::vector<unsigned char> base64Decode(const std::string &data);
};

#endif //CORE_STORAGE_ENCRYPTED_VAULT_STORAGE_H
