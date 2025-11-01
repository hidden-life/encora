#ifndef CORE_STORAGE_VAULT_EXPORTER_H
#define CORE_STORAGE_VAULT_EXPORTER_H

#include <vector>
#include <string>

/**
 * VaultExporter (v1: directory export)
 *
 * Exports the current on-disk vault into a reproducible directory "archive":
 *  <dst>/
 *      vault.meta
 *      store/
 *          index.json
 *          record_*.bin
 *      MANIFEST.json
 *      MANIFEST.hmac
 *
 * Integrity:
 *  - MANIFEST.json contains per-file SHA256 (hex) over bytes
 *  - MANIFEST.hmac = HMAC-SHA256(MANIFEST.json, key = VMK)
 *
 * Import will verify both hashes before copying back.
 */
class VaultExporter {
public:
    // Export current vault from ./data -> <dst>
    // vmk is used ONLY for HMAC over MANIFEST.json (does not re-encrypt files).
    static bool out(const std::string &dst, const std::vector<unsigned char> &vmk, std::string &errorMsg);
    // Import vault from <src> into ./data (overwriting existing files).
    // vmk is required to verify MANIFEST.hmac before trusting contents.
    static bool in(const std::string &src, const std::vector<unsigned char> &vmk, std::string &errorMsg);
};

#endif //CORE_STORAGE_VAULT_EXPORTER_H
