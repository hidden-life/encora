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

    // 1. Derive key from password
    EncoraLogger::Logger::log(EncoraLogger::Level::Debug, "Key derivation started.");
    const auto salt = std::vector<unsigned char>{ 0x01, 0x02, 0x03, 0x04 };
    auto key = KeyDerivation::derive(password, salt);

    // 2. TODO: decrypt VMK and verify integrity/signature
    // Just now we assume success.
    EncoraLogger::Logger::log(EncoraLogger::Level::Info, "Vault unlocked successfully.");
    m_isUnlocked = true;
    return true;
}

void VaultManager::lock() {
    if (m_isUnlocked) {
        EncoraLogger::Logger::log(EncoraLogger::Level::Info, "Vault is locked.");
    }

    m_isUnlocked = false;
}

bool VaultManager::isUnlocked() const { return m_isUnlocked; }

std::optional<std::string> VaultManager::debugStatus() const {
    if (m_isUnlocked) {
        return std::optional<std::string>("Vault is unlocked.");
    }

    return std::nullopt;
}
