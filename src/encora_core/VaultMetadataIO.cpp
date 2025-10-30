#include <nlohmann/json.hpp>
#include <filesystem>
#include <fstream>

#include "VaultMetadataIO.h"
#include "utils/Base64.h"
#include "utils/HMAC.h"

using json = nlohmann::json;
namespace fs = std::filesystem;

VaultMetadata VaultMetadataIO::load(const std::string &path, const std::vector<unsigned char> &derived) {
    std::ifstream ifs(path);
    if (!ifs.is_open()) {
        throw std::runtime_error("Could not open file '" + path + "' for reading.");
    }

    json j;
    ifs >> j;
    ifs.close();

    const int version = j.at("version").get<int>();
    if (version > 2) {
        throw std::runtime_error("Unsupported vault metadata version.");
    }
    std::string hmacStr = j.at("hmac").get<std::string>();
    auto expected = Base64::decode(hmacStr);
    j.erase("hmac");
    std::string jsonData = j.dump();
    if (!HMAC::verify(jsonData, derived, expected)) {
        throw std::runtime_error("Vault metadata integrity check failed (HMAC mismatch).");
    }

    VaultMetadata meta;
    meta.version = version;
    meta.kdfOpsLimit = j.at("kdf_ops_limit").get<unsigned long long>();
    meta.kdfMemLimit = j.at("kdf_mem_limit").get<unsigned long long>();
    meta.kdfSalt = Base64::decode(j.at("kdf_salt").get<std::string>());
    meta.wrappedNonce = Base64::decode(j.at("wrapped_vmk_nonce").get<std::string>());
    meta.wrappedCipherText = Base64::decode(j.at("wrapped_vmk_cipher_text").get<std::string>());
    meta.hmac = expected;

    return meta;
}

void VaultMetadataIO::save(const std::string &path, const VaultMetadata &meta, const std::vector<unsigned char> &derived) {
    json j;
    j["version"] = meta.version;
    j["kdf_ops_limit"] = meta.kdfOpsLimit;
    j["kdf_mem_limit"] = meta.kdfMemLimit;
    j["kdf_salt"] = Base64::encode(meta.kdfSalt);
    j["wrapped_vmk_nonce"] = Base64::encode(meta.wrappedNonce);
    j["wrapped_vmk_cipher_text"] = Base64::encode(meta.wrappedCipherText);

    const std::string jsonData = j.dump();
    auto hmac = HMAC::computeSha256(jsonData, derived);
    j["hmac"] = Base64::encode(hmac);

    fs::create_directories(fs::path(path).parent_path());
    std::ofstream ofs(path);
    if (!ofs.is_open()) {
        throw std::runtime_error("Failed to open vault meta for writing.");
    }

    ofs << j.dump(4);
    ofs.close();
}