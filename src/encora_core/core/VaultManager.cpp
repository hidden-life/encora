#include <sodium.h>
#include <vector>

#include "VaultManager.h"
#include "core/utils/Logger.h"
#include "secrets/KeyDerivation.h"

VaultManager::VaultManager() : m_isUnlocked(false) {}

VaultManager::~VaultManager() {
    lock();
}

bool VaultManager::unlock(const std::string &password) {
    EncoraLogger::Logger::log(EncoraLogger::Level::Info, "Attempting to unlock vault...");

    if (password.empty()) {
        EncoraLogger::Logger::log(EncoraLogger::Level::Warn, "Empty master password attempt.");
        return false;
    }

    // Ensure libsodium is initialized
    if (sodium_init() < 0) {
        EncoraLogger::Logger::log(EncoraLogger::Level::Error, "sodium_init() failed in VaultManager.");
        return false;
    }

    // In real vault, this salt would be loaded from persistent vault metadata.
    // For now, we simulate a stable salt to make sure derivation is deterministic.
    std::vector<unsigned char> salt(crypto_pwhash_SALTBYTES, 0xA5);

    // NOTE: later
    //      - when vault is first created, generate random salt:
    //          randombytes_buf(salt.data(), salt.size())
    //      - save salt in vault metadata file
    //      - on unlock, read salt and reuse it
    KdfParams params = KeyDerivation::defaultParams();
    std::vector<unsigned char> derivedKey;
    try {
        derivedKey = KeyDerivation::derive(password, salt, params);
    } catch (const std::exception &e) {
        EncoraLogger::Logger::log(EncoraLogger::Level::Error,  std::string("Key derivation failed: ") + e.what());
        return false;
    }

    // SECURITY NOTE:
    // At this point, derivedKey is the password-derived key.
    // In a real implementation we would now:
    //  1. Decrypt the vault master key (VMK) using derivedKey.
    //  2. Verify integrity/MAC.
    //  3. Store VMK securely in memory for active session.
    //
    // For now we'll just consider "unlock successful"
    m_isUnlocked = true;

    EncoraLogger::Logger::log(EncoraLogger::Level::Info, "Vault unlocked (placeholder).");

    return true;
}

void VaultManager::lock() {
    if (m_isUnlocked) {
        EncoraLogger::Logger::log(EncoraLogger::Level::Info, "Vault is locked.");
    }

    m_isUnlocked = false;

    // In the future we will:
    //  - wipe VMK from memory with SecureWiper
    //  - zeroize sensitive buffers
}

bool VaultManager::isUnlocked() const { return m_isUnlocked; }

std::optional<std::string> VaultManager::debugStatus() const {
    if (m_isUnlocked) {
        return std::optional<std::string>("Vault is unlocked.");
    }

    return std::nullopt;
}
