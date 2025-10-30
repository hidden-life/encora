#include <sodium.h>
#include <filesystem>
#include <fstream>
#include <nlohmann/json.hpp>

#include "EncryptedVaultStorage.h"
#include "utils/Base64.h"

namespace fs = std::filesystem;
using json = nlohmann::json;

EncryptedVaultStorage::EncryptedVaultStorage(const std::vector<unsigned char> &vmk) : m_vmk(vmk) {
    ensureStorageDir();
}

void EncryptedVaultStorage::ensureStorageDir() const {
    fs::create_directories("data/vault_store");
}

std::string EncryptedVaultStorage::path(const std::string &id) const {
    return "data/vault_store/record_i" + id + ".bin";
}

bool EncryptedVaultStorage::addRecord(const std::string &name, const std::string &type, std::vector<unsigned char> &data) {
    std::vector<unsigned char> nonce(crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
    randombytes_buf(nonce.data(), nonce.size());

    std::vector<unsigned char> cipherText(data.size() + crypto_aead_xchacha20poly1305_ietf_ABYTES);
    unsigned long long cipherTextLength;
    crypto_aead_xchacha20poly1305_ietf_encrypt(
        cipherText.data(),
        &cipherTextLength,
        data.data(),
        data.size(),
        nullptr,
        0,
        nullptr,
        nonce.data(),
        m_vmk.data()
        );

    cipherText.resize(cipherTextLength);

    std::string id = std::to_string(std::chrono::system_clock::now().time_since_epoch().count());
    std::ofstream ofs(path(id), std::ios::binary);
    ofs.write((char*)nonce.data(), nonce.size());
    ofs.write((char*)cipherText.data(), cipherText.size());
    ofs.close();

    json j = {
        {"id", id},
        {"name", name},
        {"type", type},
        {"created_at", std::time(nullptr)}
    };

    std::ofstream idx("data/vault_store/index.json", std::ios::app);
    idx << j.dump() << std::endl;

    return true;
}

std::vector<unsigned char> EncryptedVaultStorage::loadRecord(const std::string &name) {
    std::ifstream idx("data/vault_store/index.json");
    std::string line;
    std::string id;

    while (std::getline(idx, line)) {
        auto j = json::parse(line);
        if (j["name"] == name) {
            id = j["id"];
            break;
        }
    }

    if (id.empty()) {
        throw std::runtime_error("Record does not exist.");
    }

    std::ifstream ifs(path(id), std::ios::binary);
    std::vector<unsigned char> nonce(crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
    ifs.read((char*)nonce.data(), nonce.size());

    std::vector<unsigned char> cipherText((std::istreambuf_iterator<char>(ifs)), {});
    ifs.close();

    std::vector<unsigned char> decrypted(cipherText.size());
    unsigned long long decryptedLength;
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(decrypted.data(), &decryptedLength, nullptr, cipherText.data(), cipherText.size(), nullptr, 0 , nonce.data(), m_vmk.data()) != 0) {
        throw std::runtime_error("Failed to decrypt record.");
    }

    decrypted.resize(decryptedLength);
    return decrypted;
}

std::vector<std::string> EncryptedVaultStorage::list() const {
    std::ifstream idx("data/vault_store/index.json");
    std::string line;
    std::vector<std::string> records;
    while (std::getline(idx, line)) {
        auto j = json::parse(line);
        records.push_back(j["name"]);
    }

    return records;
}
