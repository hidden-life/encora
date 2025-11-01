#include <filesystem>
#include <nlohmann/json.hpp>
#include <fstream>
#include <sodium.h>
#include <iomanip>

#include "ManifestWriter.h"
#include "utils/Logger.h"

namespace fs = std::filesystem;
using json = nlohmann::json;

static std::vector<unsigned char> readAll(const fs::path &path) {
    std::ifstream ifs(path, std::ios::binary);
    if (!ifs.is_open()) {
        throw std::runtime_error("ManifestWriter: cannot open: " + path.string());
    }

    return std::vector<unsigned char>((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
}

static void writeAll(const fs::path &path, const std::vector<unsigned char> &data) {
    fs::create_directories(path.parent_path());
    std::ofstream ofs(path, std::ios::binary | std::ios::trunc);
    if (!ofs.is_open()) {
        throw std::runtime_error("ManifestWriter: cannot write: " + path.string());
    }

    if (!data.empty()) {
        ofs.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
        if (!ofs.good()) {
            throw std::runtime_error("ManifestWriter: cannot write to file: " + path.string());
        }
    }

    ofs.close();
}

static std::string toHex(const unsigned char *buffer, size_t length) {
    std::ostringstream oss;
    for (size_t i = 0; i < length; ++i) {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(buffer[i]);
    }

    return oss.str();
}

static std::string sha256Hex(const std::vector<unsigned char> &bytes) {
    unsigned char out[crypto_hash_sha256_BYTES];
    crypto_hash_sha256(out, bytes.data(), bytes.size());
    return toHex(out, sizeof(out));
}

static std::vector<unsigned char> hmacSha256(const std::string &data, const std::vector<unsigned char> &key) {
    std::vector<unsigned char> mac(crypto_auth_hmacsha256_BYTES);
    crypto_auth_hmacsha256_state state;
    crypto_auth_hmacsha256_init(&state, key.data(), key.size());
    crypto_auth_hmacsha256_update(&state, reinterpret_cast<const unsigned char*>(data.data()), data.size());
    crypto_auth_hmacsha256_final(&state, mac.data());

    return mac;
}

bool ManifestWriter::update(const std::string &root, const std::vector<unsigned char> &vmk, std::string &err) {
    try {
        if (vmk.empty()) {
            throw std::runtime_error("VMK is empty. Cannot sign manifest.");
        }

        const fs::path rootPath = root;
        fs::create_directories(rootPath);
        const fs::path metaPath = rootPath / "vault.meta";
        const fs::path storePath = rootPath / "vault_store";
        const fs::path manifestPath = rootPath / "MANIFEST.json";
        const fs::path hmacManifestPath = rootPath / "MANIFEST.hmac";

        if (!fs::exists(metaPath)) {
            throw std::runtime_error("vault.meta not found.");
        }

        json j;
        j["version"] = 1;
        j["files"] = json::array();

        auto appendWithHash = [&](const fs::path &rel) {
            const auto abs = rootPath / rel;
            if (!fs::exists(abs)) return;

            const auto bytes = readAll(abs);

            json f = {
                {"path", rel.generic_string()},
                {"sha256", sha256Hex(bytes)}
            };
            j["files"].push_back(f);
        };

        appendWithHash("vault.meta");
        appendWithHash(fs::path("vault_store") / "index.json");

        if (fs::exists(storePath)) {
            for (auto &entry : fs::directory_iterator(storePath)) {
                if (!entry.is_regular_file()) continue;
                if (const auto name = entry.path().filename().string(); name.rfind("record_", 0) == 0 && entry.path().extension() == ".bin") {
                    appendWithHash(fs::path("vault_store") / name);
                }
            }
        }

        // Write MANIFEST.json
        {
            std::ofstream ofs(manifestPath, std::ios::binary | std::ios::trunc);
            if (!ofs.is_open()) {
                throw std::runtime_error("Failed to write MANIFEST.json");
            }
            ofs << j.dump(2);
        }

        // Write MANIFEST.hmac = HMAC(MANIFEST.json, VMK)
        const auto manifestBytes = readAll(manifestPath);
        const std::string manifestStr(manifestBytes.begin(), manifestBytes.end());
        const auto mac = hmacSha256(manifestStr, vmk);
        writeAll(hmacManifestPath, mac);

        EncoraLogger::Logger::log(EncoraLogger::Level::Info, "Manifest updated successfully.");

        return true;
    } catch (const std::exception &e) {
        err = e.what();
        EncoraLogger::Logger::log(EncoraLogger::Level::Error, std::string("Manifest updated failed: ") + e.what());

        return false;
    }
}
