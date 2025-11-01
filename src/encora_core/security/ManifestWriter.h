#ifndef CORE_SECURITY_MANIFEST_WRITER_H
#define CORE_SECURITY_MANIFEST_WRITER_H

#include <string>
#include <vector>

/**
 * ManifestWriter regenerates MANIFEST.json and MANIFEST.hmac in the live vault root (e.g., "data/").
 * MANIFEST.json lists SHA-256 hashes for:
 *      - vault.meta
 *      - vault_store/index.json (if exists)
 *      - vault_store/record_*.bin (each record)
 * MANIFEST.hmac = HMAC-SHA256 (MANIFEST.json, key = VMK)
 *
 * Call this after any mutation (add/remove) to keep integrity up-to-date.
 */
class ManifestWriter {
public:
    // Recalculate and write MANIFEST.{json, hmac} under root using VMK.
    // Returns true on success; on failure returns false and fills err.
    static bool update(const std::string &root, const std::vector<unsigned char> &vmk, std::string &err);
};

#endif //CORE_SECURITY_MANIFEST_WRITER_H
