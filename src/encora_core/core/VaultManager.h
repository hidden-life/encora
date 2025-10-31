#ifndef CORE_VAULT_MANAGER_H
#define CORE_VAULT_MANAGER_H

#include <string>
#include <optional>
#include <vector>

/**
 * VaultManager
 *
 * Controls 'locked/unlocked' state of the vault.
 * Uses KeyDerivation to derive keys from master password.
 * Talks to storage backends (LocalEncryptedStorage).
 *
 * Responsible for managing the vault lifecycle:
 *      - Creating new vaults
 *      - Unlocking existing vaults
 *      - Locking and zeroizing secrets
 *
 * The vault is represented be metadata stored on disk (vault.meta)
 * and Vault Master Key kept in secure memory while unlocked.
 */
class VaultManager {
public:
    VaultManager();
    ~VaultManager();

    // Create new vault (generate salt, VMK, encrypt it, save metadata)
    bool init(const std::string &password);
    // Unlock existing vault (load metadata, derive key, decrypt VMK)
    bool unlock(const std::string &password);
    // Lock vault (wipe VMK from memory)
    void lock();
    [[nodiscard]]
    bool isUnlocked() const;
    [[nodiscard]]
    std::optional<std::string> debugStatus() const;
    // Returns copy of VMK (COPY!), if vault in unlocked.
    [[nodiscard]]
    std::vector<unsigned char> sessionVMK() const;

private:
    bool m_isUnlocked;
    std::vector<unsigned char> m_vmk;
    // Path to metadata file (for new hardcoded)
    [[nodiscard]]
    std::string metaPath() const;
};

#endif //CORE_VAULT_MANAGER_H
