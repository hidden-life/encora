#ifndef CORE_VAULT_MANAGER_H
#define CORE_VAULT_MANAGER_H

#include <string>
#include <optional>

/**
 * VaultManager
 *
 * Controls 'locked/unlocked' state of the vault.
 * Uses KeyDerivation to derive keys from master password.
 * Talks to storage backends (LocalEncryptedStorage).
 *
 * Right now:
 *  - unlock() succeeds if password non-empty
 *  - stores internal "m_isUnlocked" flag
 */
class VaultManager {
public:
    VaultManager();
    ~VaultManager();

    bool unlock(const std::string &password);
    void lock();
    [[nodiscard]]
    bool isUnlocked() const;
    [[nodiscard]]
    std::optional<std::string> debugStatus() const;

private:
    bool m_isUnlocked;
};

#endif //CORE_VAULT_MANAGER_H
