#include <sodium.h>
#include <vector>
#include <filesystem>
#include <nlohmann/json.hpp>
#include <fstream>

#include "VaultManager.h"
#include "VaultMetadata.h"
#include "VaultMetadataIO.h"
#include "core/utils/Logger.h"
#include "secrets/KeyDerivation.h"
#include "secrets/KeyWrap.h"
#include "utils/Base64.h"

using json = nlohmann::json;

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
    const KdfParams params = KeyDerivation::defaultParams();
    // Generate random salt
    std::vector<unsigned char> salt(crypto_pwhash_SALTBYTES);
    randombytes_buf(salt.data(), salt.size());
    // Derive key from password
    const std::vector<unsigned char> derivedKey = KeyDerivation::derive(password, salt, params);

    // Generate VMK (Vault Master Key).
    std::vector<unsigned char> vmk(32);
    randombytes_buf(vmk.data(), vmk.size());

    // Encrypt (wrap) VMK
    WrappedKey wrapped = KeyWrap::wrap(vmk, derivedKey);

    // Prepare metadata
    VaultMetadata metadata;
    metadata.version = 2;
    metadata.kdfOpsLimit = params.opsLimit;
    metadata.kdfMemLimit = params.memLimit;
    metadata.kdfSalt = salt;
    metadata.wrappedNonce = wrapped.nonce;
    metadata.wrappedCipherText = wrapped.cipherText;

    // Save metadata with HMAC
    try {
        std::filesystem::create_directories("data");
        VaultMetadataIO::save(metaPath(), metadata, derivedKey);
    } catch (const std::exception &e) {
        EncoraLogger::Logger::log(EncoraLogger::Level::Error, std::string("Failed to save vault meta: ") + e.what());
        return false;
    }

    EncoraLogger::Logger::log(EncoraLogger::Level::Info, "Vault initialized successfully.");
    return true;
}

bool VaultManager::unlock(const std::string &password) {
    EncoraLogger::Logger::log(EncoraLogger::Level::Info, "VaultManager::unlock: called.");

    VaultMetadata metadata;
    std::vector<unsigned char> derived;
    try {
        // Read first the file to extract KDF parameters.
        json tmp;
        std::ifstream ifs(metaPath());
        if (!ifs.is_open()) {
            throw std::runtime_error("Vault metadata not found.");
        }

        ifs >> tmp;
        ifs.close();

        unsigned long long ops = tmp.at("kdf_ops_limit").get<unsigned long long>();
        unsigned long long mem = tmp.at("kdf_mem_limit").get<unsigned long long>();
        std::vector<unsigned char> salt = Base64::decode(tmp.at("kdf_salt").get<std::string>());

        KdfParams params {ops, static_cast<size_t>(mem)};
        derived = KeyDerivation::derive(password, salt, params);
        metadata = VaultMetadataIO::load(metaPath(), derived);
    } catch (std::exception &e) {
        EncoraLogger::Logger::log(EncoraLogger::Level::Error, std::string("Failed to load vault metadata: ") + e.what());
        return false;
    }

    // Now we need to unwrap VMK
    WrappedKey wrapped {metadata.wrappedNonce, metadata.wrappedCipherText};
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
