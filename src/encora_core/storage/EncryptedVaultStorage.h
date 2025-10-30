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
    std::vector<std::string> list() const;

private:
    std::vector<unsigned char> m_vmk;
    std::string path(const std::string &id) const;
    void ensureStorageDir() const;
};

#endif //CORE_STORAGE_ENCRYPTED_VAULT_STORAGE_H
