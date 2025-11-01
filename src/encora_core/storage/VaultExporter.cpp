#include <filesystem>
#include <fstream>
#include <vector>
#include <string>
#include <sstream>
#include <iomanip>
#include <stdexcept>

#include <sodium.h>
#include <nlohmann/json.hpp>

#include "VaultExporter.h"
#include "utils/Logger.h"

namespace fs = std::filesystem;
using json = nlohmann::json;

static std::vector<unsigned char> readAll(const fs::path &path) {
    std::ifstream ifs(path, std::ios::binary);
    if (!ifs.is_open()) {
        throw std::runtime_error("Failed to open file: " + path.string());
    }

    return std::vector<unsigned char>((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
}

static void writeAll(const fs::path &path, const std::vector<unsigned char> &data) {
    fs::create_directories(path.parent_path());
    std::ofstream ofs(path, std::ios::binary | std::ios::trunc);
    if (!ofs.is_open()) {
        throw std::runtime_error("Failed to write file: " + path.string());
    }

    ofs.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
}

static std::string toHex(const unsigned char *buffer, size_t length) {
    std::stringstream ss;
    for (size_t i = 0; i < length; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(buffer[i]);
    }
    return ss.str();
}

static std::string sha256Hex(const std::vector<unsigned char> &bytes) {
    unsigned char out[crypto_hash_sha256_BYTES];
    crypto_hash_sha256(out, bytes.data(), bytes.size());
    return toHex(out, crypto_hash_sha256_BYTES);
}

static std::vector<unsigned char> hmacSha256(const std::string &data, const std::vector<unsigned char> &key) {
    std::vector<unsigned char> mac(crypto_auth_hmacsha256_BYTES);
    crypto_auth_hmacsha256_state state;
    crypto_auth_hmacsha256_init(&state, key.data(), key.size());
    crypto_auth_hmacsha256_update(&state, reinterpret_cast<const unsigned char*>(data.data()), data.size());
    crypto_auth_hmacsha256_final(&state, mac.data());

    return mac;
}

static bool verifyHmacSha256(const std::string &data, const std::vector<unsigned char> &key, const std::vector<unsigned char> &expected) {
    auto mac = hmacSha256(data, key);
    return sodium_memcmp(mac.data(), expected.data(), mac.size()) == 0;
}

static void copyTo(const fs::path &src, const fs::path &dst) {
    fs::create_directories(dst.parent_path());
    fs::copy_file(src, dst, fs::copy_options::overwrite_existing);
}

bool VaultExporter::out(const std::string &dst, const std::vector<unsigned char> &vmk, std::string &errorMsg) {
    try {
        // 1. Validate input and source layout
        if (vmk.empty()) {
            throw std::runtime_error("VMK is empty (vault is not unlocked).");
        }

        const fs::path srcData = "data";
        const fs::path srcMeta = srcData / "vault.meta";
        const fs::path srcStore = srcData / "vault_store";
        if (!fs::exists(srcMeta)) {
            throw std::runtime_error("Source 'data/vault.meta not found.'");
        }
        if (!fs::exists(srcStore)) {
            // allowed: empty store, create manifest for meta only
        }

        // 2. Prepare destination
        const fs::path destDir = dst;
        const fs::path destMeta = destDir / "vault.meta";
        const fs::path destStore = destDir / "store";
        const fs::path destManifest = destDir / "MANIFEST.json";
        const fs::path destHmac = destDir / "MANIFEST.hmac";

        // Clean or create
        if (fs::exists(destDir)) {
            // allow to overwrite
            // NOTE: we selectively overwrite files below
        } else {
            fs::create_directories(destDir);
        }

        fs::create_directories(destStore);

        // 3. Copy files
        copyTo(srcMeta, destMeta);
        if (fs::exists(srcStore)) {
            const fs::path srcIdx = srcStore / "index.json";
            if (fs::exists(srcIdx)) {
                copyTo(srcIdx, destStore / "index.json");
            }

            for (auto &entry : fs::directory_iterator(srcStore)) {
                if (!entry.is_regular_file()) continue;
                const auto name = entry.path().filename().string();
                if (name.rfind("record_", 0) == 0 && entry.path().extension() == ".bin") {
                    copyTo(entry.path(), destStore / name);
                }
            }
        }

        // 4. Build MANIFEST.json: list + sha256
        json manifestJson;
        manifestJson["version"] = 1;
        manifestJson["files"] = json::array();

        auto appendWithHash = [&](const fs::path &relPath) {
            const auto bytes = readAll(destDir / relPath);
            json f = {
                {"path", relPath.generic_string()},
                {"sha256", sha256Hex(bytes)}
            };
            manifestJson["files"].push_back(f);
        };

        appendWithHash("vault.meta");

        if (fs::exists(destStore / "index.json")) {
            appendWithHash(fs::path("vault_store") / "index.json");
        }

        if (fs::exists(destStore)) {
            for (auto &entry : fs::directory_iterator(destStore)) {
                if (!entry.is_regular_file()) continue;
                const auto name = entry.path().filename().string();
                if (name.rfind("record_", 0) == 0 && entry.path().extension() == ".bin") {
                    appendWithHash(fs::path("vault_store") / name);
                }
            }
        }

        // 5. Write MANIFEST.json
        {
            std::ofstream ofs(destManifest, std::ios::binary | std::ios::trunc);
            if (!ofs.is_open()) {
                throw std::runtime_error("Failed to write MANIFEST.json");
            }
            ofs << manifestJson.dump(2);
        }

        // 6. Write MANIFEST.hmac = HMAC(MANIFEST.json, vmk)
        const auto manifestTxt = readAll(destManifest);
        const std::string manifestStr(manifestTxt.begin(), manifestTxt.end());
        const auto mac = hmacSha256(manifestStr, vmk);
        writeAll(destHmac, mac);

        EncoraLogger::Logger::log(EncoraLogger::Level::Info, "Export completed: " + destDir.string());
        return true;
    } catch (const std::exception &e) {
        errorMsg = e.what();
        EncoraLogger::Logger::log(EncoraLogger::Level::Error, std::string("Export failed: ") + e.what());
        return false;
    }
}

bool VaultExporter::in(const std::string &src, const std::vector<unsigned char> &vmk, std::string &errorMsg) {
    try {
        // Temporary allow empty VMK
        const bool verifyHmac = !vmk.empty();

        const fs::path srcDir = src;
        const fs::path manifest = srcDir / "MANIFEST.json";
        const fs::path hmac = srcDir / "MANIFEST.hmac";
        const fs::path meta = srcDir / "vault.meta";
        const fs::path store = srcDir / "store";

        if (!fs::exists(manifest) || !fs::exists(hmac) || !fs::exists(meta)) {
            throw std::runtime_error("Invalid export folder (missing files).");
        }

        if (verifyHmac) {
            // Verify HMAC
            const auto manifestBytes = readAll(manifest);
            const std::string manifestStr(manifestBytes.begin(), manifestBytes.end());
            const auto mac = readAll(hmac);

            if (mac.size() != crypto_auth_hmacsha256_BYTES) {
                throw std::runtime_error("Invalid MANIFEST.hmac size.");
            }

            if (!verifyHmacSha256(manifestStr, vmk, mac)) {
                throw std::runtime_error("HMAC verification failed.");
            }
        }

        // Verify SHA-256 per-file
        const auto manifestBytes = readAll(manifest);
        const std::string manifestStr(manifestBytes.begin(), manifestBytes.end());
        const auto j = json::parse(manifestStr);
        for (const auto &f : j.at("files")) {
            const fs::path rel = f.at("path").get<std::string>();
            const fs::path abs = srcDir / rel;
            if (!fs::exists(abs)) {
                throw std::runtime_error("Missing file in export: " + abs.string());
            }

            const auto bytes = readAll(abs);
            const auto got = sha256Hex(bytes);
            const auto want = f.at("sha256").get<std::string>();
            if (got != want) {
                throw std::runtime_error("Hash mismatch for: " + abs.string());
            }
        }

        // Copy into ./data (overwrite)
        const fs::path destData = "data";
        const fs::path destMeta = destData / "vault.meta";
        const fs::path destStore = destData / "store";
        fs::create_directories(destStore);

        copyTo(meta, destMeta);

        if (fs::exists(store / "index.json")) {
            copyTo(store / "index.json", destStore / "index.json");
        }

        for (auto &entry : fs::directory_iterator(store)) {
            if (!entry.is_regular_file()) continue;
            const auto name = entry.path().filename().string();
            if (name.rfind("record_", 0) == 0 && entry.path().extension() == ".bin") {
                copyTo(entry.path(), destStore / name);
            }
        }

        copyTo(srcDir / "MANIFEST.json", destData / "MANIFEST.json");
        copyTo(srcDir / "MANIFEST.hmac", destData / "MANIFEST.hmac");

        EncoraLogger::Logger::log(EncoraLogger::Level::Info, "Import completed from: " + srcDir.string());
        return true;
    } catch (const std::exception &e) {
        errorMsg = e.what();
        EncoraLogger::Logger::log(EncoraLogger::Level::Error, std::string("Import failed: ") + e.what());
        return false;
    }
}

