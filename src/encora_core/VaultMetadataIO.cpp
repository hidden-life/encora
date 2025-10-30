#include <nlohmann/json.hpp>
#include <filesystem>
#include <fstream>

#include "VaultMetadataIO.h"
#include "utils/Base64.h"

using json = nlohmann::json;
namespace fs = std::filesystem;

VaultMetadata VaultMetadataIO::load(const std::string &path) {
    std::ifstream ifs(path);
    if (!ifs.is_open()) {
        throw std::runtime_error("Could not open file '" + path + "' for reading.");
    }

    json j;
    ifs >> j;
    ifs.close();

    VaultMetadata meta;
    meta.version = j.at("version").get<int>();
    meta.kdfOpsLimit = j.at("kdf_ops_limit").get<unsigned long long>();
    meta.kdfMemLimit = j.at("kdf_mem_limit").get<unsigned long long>();
    meta.kdfSalt = Base64::decode(j.at("kdf_salt").get<std::string>());
    meta.wrappedNonce = Base64::decode(j.at("wrapped_vmk_nonce").get<std::string>());
    meta.wrappedCipherText = Base64::decode(j.at("wrapped_vmk_cipher_text").get<std::string>());

    return meta;
}

void VaultMetadataIO::save(const std::string &path, const VaultMetadata &meta) {
    json j;
    j["version"] = meta.version;
    j["kdf_ops_limit"] = meta.kdfOpsLimit;
    j["kdf_mem_limit"] = meta.kdfMemLimit;
    j["kdf_salt"] = Base64::encode(meta.kdfSalt);
    j["wrapped_vmk_nonce"] = Base64::encode(meta.wrappedNonce);
    j["wrapped_vmk_cipher_text"] = Base64::encode(meta.wrappedCipherText);

    fs::create_directories(fs::path(path).parent_path());
    printf("[DEBUG] dirs ok, opening file: %s\n", path.c_str());
    fflush(stdout);
    std::ofstream ofs(path);
    if (!ofs.is_open()) {
        printf("[DEBUG] failed to open file for write!\n");
        throw std::runtime_error("Failed to open vault meta for writing.");
    }

    ofs << j.dump(4);
    ofs.close();

    printf("[DEBUG] JSON written successfully\n");
}