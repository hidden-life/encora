#include <sodium.h>
#include <vector>

#include "VaultManager.h"

#include <filesystem>

#include "VaultMetadata.h"
#include "VaultMetadataIO.h"
#include "core/utils/Logger.h"
#include "secrets/KeyDerivation.h"
#include "secrets/KeyWrap.h"

VaultManager::VaultManager() : m_isUnlocked(false) {
    sodium_init(); // safe to call multiple times :)
}

VaultManager::~VaultManager() {
    lock();
}

bool VaultManager::init(const std::string &password) {
    EncoraLogger::Logger::log(EncoraLogger::Level::Info, "VaultManager::init: called.");
    if (password.empty()) {
        EncoraLogger::Logger::log(EncoraLogger::Level::Warn, "Cannot initialize vault: empty password.");
        return false;
    }

    // Generate KDF parameters
    KdfParams params = KeyDerivation::defaultParams();
    // Generate random salt
    std::vector<unsigned char> salt(crypto_pwhash_SALTBYTES);
    randombytes_buf(salt.data(), salt.size());
    // Derive key from password
    std::vector<unsigned char> derivedKey;
    try {
        derivedKey = KeyDerivation::derive(password, salt, params);
    } catch (const std::exception &e) {
        EncoraLogger::Logger::log(EncoraLogger::Level::Error, std::string("Key derivation failed.") + e.what());
        return false;
    }

    // Generate VMK (Vault Master Key).
    std::vector<unsigned char> vmk(32);
    randombytes_buf(vmk.data(), vmk.size());

    // Encrypt (wrap) VMK
    WrappedKey wrapped = KeyWrap::wrap(vmk, derivedKey);

    // Prepare metadata
    VaultMetadata metadata;
    metadata.version = 1;
    metadata.kdfOpsLimit = params.opsLimit;
    metadata.kdfMemLimit = params.memLimit;
    metadata.kdfSalt = salt;
    metadata.wrappedNonce = wrapped.nonce;
    metadata.wrappedCipherText = wrapped.cipherText;

    // Save metadata
    try {
        std::filesystem::create_directories("data");
        VaultMetadataIO::save(metaPath(), metadata);
    } catch (const std::exception &e) {
        EncoraLogger::Logger::log(EncoraLogger::Level::Error, std::string("Failed to save vault meta: ") + e.what());
        return false;
    }

    EncoraLogger::Logger::log(EncoraLogger::Level::Info, "Vault initialized successfully.");
    return true;
}

bool VaultManager::unlock(const std::string &password) {
    EncoraLogger::Logger::log(EncoraLogger::Level::Info, "VaultManager::unlock: called.");

    if (password.empty()) {
        EncoraLogger::Logger::log(EncoraLogger::Level::Warn, "Cannot unlock vault: empty password.");
        return false;
    }

    VaultMetadata metadata;
    try {
        metadata = VaultMetadataIO::load(metaPath());
    } catch (const std::exception &e) {
        EncoraLogger::Logger::log(EncoraLogger::Level::Error, std::string("Failed to load vault metadata: ") + e.what());
        return false;
    }

    const KdfParams params {
        metadata.kdfOpsLimit,
        static_cast<size_t>(metadata.kdfMemLimit),
    };

    std::vector<unsigned char> derived;
    try {
        derived = KeyDerivation::derive(password, metadata.kdfSalt, params);
    } catch (const std::exception &e) {
        EncoraLogger::Logger::log(EncoraLogger::Level::Error, std::string("Key derivation failed: ") + e.what());
        return false;
    }

    WrappedKey wrapped;
    wrapped.nonce = metadata.wrappedNonce;
    wrapped.cipherText = metadata.wrappedCipherText;

    try {
        m_vmk = KeyWrap::unwrap(wrapped, derived);
    } catch (const std::exception &e) {
        EncoraLogger::Logger::log(EncoraLogger::Level::Error, std::string("Failed to unwrap vault: ") + e.what());
        return false;
    }

    m_isUnlocked = true;
    EncoraLogger::Logger::log(EncoraLogger::Level::Info, "Vault unlocked successfully.");

    return true;
}

void VaultManager::lock() {
    if (!m_vmk.empty()) {
        EncoraLogger::Logger::log(EncoraLogger::Level::Info, "VaultManager::lock: called.");
        sodium_memzero(m_vmk.data(), m_vmk.size());
        m_vmk.clear();
    }

    m_isUnlocked = false;
    EncoraLogger::Logger::log(EncoraLogger::Level::Info, "Vault locked and memory wiped.");
}

bool VaultManager::isUnlocked() const { return m_isUnlocked; }

std::optional<std::string> VaultManager::debugStatus() const {
    if (m_isUnlocked) {
        return "Vault is unlocked.";
    }

    return std::nullopt;
}

std::string VaultManager::metaPath() const {
    // Later it will be platform-specific.
    return "data/vault.meta";
}
