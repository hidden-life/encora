#include <filesystem>
#include <nlohmann/json.hpp>
#include <fstream>
#include <sodium.h>

#include "IntegrityChecker.h"

namespace fs = std::filesystem;
using json = nlohmann::json;

static std::vector<unsigned char> readAll(const fs::path &path, bool &ok) {
    ok = false;
    std::ifstream ifs(path, std::ios::binary);
    if (!ifs.is_open()) return {};
    std::vector<unsigned char> bytes((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());

    ok = true;
    return bytes;
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
    crypto_auth_hmacsha256_update(&state, reinterpret_cast<const unsigned char *>(data.data()), data.size());
    crypto_auth_hmacsha256_final(&state, mac.data());

    return mac;
}

IntegrityReport IntegrityChecker::verify(const std::string &root, const std::vector<unsigned char> &vmk) {
    IntegrityReport report;

    try {
        const fs::path rootPath = root;
        const fs::path manifestPath = rootPath / "MANIFEST.json";
        const fs::path hmacPath = rootPath / "MANIFEST.hmac";

        if (!fs::exists(manifestPath) || !fs::exists(hmacPath)) {
            report.status = IntegrityStatus::MissingManifest;
            report.message = "MANIFEST.* not found.";

            return report;
        }

        bool isOk = false;
        const auto manifestBytes = readAll(manifestPath, isOk);
        if (!isOk) {
            report.status = IntegrityStatus::Error;
            report.message = "Failed to read MANIFEST.json.";
            return report;
        }

        const std::string manifestStr(manifestBytes.begin(), manifestBytes.end());
        const auto macBytes = readAll(hmacPath, isOk);
        if (!isOk) {
            report.status = IntegrityStatus::Error;
            report.message = "Failed to read MANIFEST.hmac.";
            return report;
        }

        if (macBytes.size() != crypto_auth_hmacsha256_BYTES) {
            report.status = IntegrityStatus::Error;
            report.message = "Invalid MANIFEST.hmac size.";
            return report;
        }

        // If VMK is empty, we cannot authenticate manifest -> HMAC mismatch
        if (vmk.empty()) {
            report.status = IntegrityStatus::HMACMismatch;
            report.message = "VMK is empty. Cannot verify HMAC.";
            return report;
        }

        // Verify HMAC (MANIFEST.json, VMK)
        const auto macCalculated = hmacSha256(manifestStr, vmk);
        if (sodium_memcmp(macCalculated.data(), macBytes.data(), macCalculated.size()) != 0) {
            report.status = IntegrityStatus::HMACMismatch;
            report.message = "HMAC verification failed.";
            return report;
        }

        // Verify per-file SHA256
        const auto j = json::parse(manifestStr, nullptr, true);
        if (!j.contains("files") || !j["files"].is_array()) {
            report.status = IntegrityStatus::Error;
            report.message = "MANIFEST.json malformed: missing 'files'.";
            return report;
        }

        for (const auto &f : j["files"]) {
            const auto rel = f.at("path").get<std::string>();
            const auto want = f.at("sha256").get<std::string>();
            const fs::path abs = rootPath / fs::path(rel);

            if (!fs::exists(abs)) {
                report.status = IntegrityStatus::HashMismatch;
                report.message = "Missing file listed in MANIFEST: " + abs.string();
                return report;
            }

            bool isOKF = false;
            const auto bytes = readAll(abs, isOKF);
            if (!isOKF) {
                report.status = IntegrityStatus::Error;
                report.message = "Failed to read: " + abs.string();
                return report;
            }

            const auto got = sha256Hex(bytes);
            if (got != want) {
                report.status = IntegrityStatus::HashMismatch;
                report.message = "Hash mismatch for: " + abs.string();
                return report;
            }
        }

        report.status = IntegrityStatus::OK;
        report.message = "Vault integrity verified.";

        return report;
    } catch (const std::exception &e) {
        report.status = IntegrityStatus::Error;
        report.message = e.what();

        return report;
    }
}
