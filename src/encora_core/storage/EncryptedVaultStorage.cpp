#include <sodium.h>
#include <filesystem>
#include <fstream>
#include <nlohmann/json.hpp>

#include "EncryptedVaultStorage.h"
#include "utils/Base64.h"

namespace fs = std::filesystem;
using json = nlohmann::json;

static inline void strip_cr(std::string& str) {
    str.erase(std::remove(str.begin(), str.end(), '\r'), str.end());
}

static inline bool safeParseLine(const std::string &line, json &out) {
    if (line.empty()) return false;
    auto j = json::parse(line, nullptr, false);
    if (j.is_discarded()) return false;
    out = std::move(j);

    return true;
}

static bool rewrite(const std::string &name) {
    std::ifstream ifs("data/vault_store/index.json");
    if (!ifs.is_open()) {
        return true;
    }

    std::vector<std::string> lines;
    std::string line;
    while (std::getline(ifs, line)) {
        if (line.empty()) continue;
        json j = json::parse(line, nullptr, false);
        if (j.is_discarded()) continue;
        if (j.value("name", "") != name) {
            lines.push_back(line);
        }
    }

    ifs.close();

    std::ofstream ofs("data/vault_store/index.json", std::ios::trunc);
    if (!ofs.is_open()) {
        return false;
    }

    for (auto &l : lines) {
        ofs << l << "\n";
    }

    return true;
}

EncryptedVaultStorage::EncryptedVaultStorage(const std::vector<unsigned char> &vmk) : m_vmk(vmk) {
    ensureStorageDir();
}

void EncryptedVaultStorage::ensureStorageDir() const {
    fs::create_directories("data/vault_store");
}

std::string EncryptedVaultStorage::path(const std::string &id) const {
    return "data/vault_store/record_" + id + ".bin";
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
    if (!ofs.is_open()) {
        throw std::runtime_error("Cannot open record file for write.");
    }

    rewrite(name);
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
    if (!idx.is_open()) {
        throw std::runtime_error("Cannot open index for append.");
    }
    idx << j.dump() << std::endl;

    return true;
}

std::vector<unsigned char> EncryptedVaultStorage::loadRecord(const std::string &name) {
    std::ifstream idx("data/vault_store/index.json");
    if (!idx.is_open()) {
        throw std::runtime_error("Index file not found.");
    }
    std::string line;
    std::string id;

    while (std::getline(idx, line)) {
        strip_cr(line);
        json j;
        if (!safeParseLine(line, j)) continue;

        // Safely read name and compare
        const auto n = j.value("name", std::string{});
        if (n == name) {
            id = j.value("id", std::string{});
            break;
        }
    }

    idx.close();

    if (id.empty()) {
        throw std::runtime_error("Record does not exist.");
    }

    std::ifstream ifs(path(id), std::ios::binary);
    if (!ifs.is_open()) {
        throw std::runtime_error("Cannot open record file. Not found: " + path(id));
    }

    ifs.seekg(0, std::ios::end);
    const auto sz = static_cast<size_t>(ifs.tellg());
    ifs.seekg(0);
    if (sz < crypto_aead_xchacha20poly1305_ietf_NPUBBYTES) {
        throw std::runtime_error("Record file corrupted: too small.");
    }

    std::vector<unsigned char> nonce(crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
    ifs.read(reinterpret_cast<char*>(nonce.data()), nonce.size());
    std::vector<unsigned char> cipherText((std::istreambuf_iterator<char>(ifs)), {});
    ifs.close();

    std::vector<unsigned char> decrypted(cipherText.size());
    unsigned long long decryptedLength = 0;
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(
        decrypted.data(),
        &decryptedLength,
        nullptr,
        cipherText.data(),
        cipherText.size(),
        nullptr,
        0 ,
        nonce.data(),
        m_vmk.data()
        ) != 0) {
        throw std::runtime_error("Failed to decrypt record.");
    }

    decrypted.resize(decryptedLength);
    return decrypted;
}

std::vector<std::string> EncryptedVaultStorage::list() const {
    std::vector<std::string> records;
    std::ifstream idx("data/vault_store/index.json");
    if (!idx.is_open()) return records;
    std::string line;
    while (std::getline(idx, line)) {
        strip_cr(line);
        json j;
        if (!safeParseLine(line, j)) continue;

        // There is no name or be as string
        if (j.contains("name") && j["name"].is_string()) {
            records.push_back(j["name"].get<std::string>());
        }
    }

    return records;
}

bool EncryptedVaultStorage::remove(const std::string &name) {
    const std::string idxPath = "data/vault_store/index.json";
    std::ifstream idx(idxPath);
    if (!idx.is_open()) {
        throw std::runtime_error("Index file not found.");
    }

    std::vector<json> records;
    std::string line;
    std::string targetId;
    while (std::getline(idx, line)) {
        if (line.empty()) continue;
        line.erase(std::remove(line.begin(), line.end(), '\r'), line.end());
        auto j = json::parse(line);
        if (j["name"] == name) {
            targetId = j["id"];
            continue; // skip to delete
        }
        records.push_back(j);
    }

    idx.close();

    if (targetId.empty()) {
        throw std::runtime_error("Record does not exist: " + name);
    }

    // Delete corresponding encrypted file
    std::string recordPath = path(targetId);
    if (fs::exists(recordPath)) {
        fs::remove(recordPath);
    }

    // Remove index.json without deleted record
    std::ofstream idxOut(idxPath, std::ios::trunc);
    for (const auto &rec : records) {
        idxOut << rec.dump() << std::endl;
    }
    idxOut.close();

    return true;
}

