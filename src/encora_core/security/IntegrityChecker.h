#ifndef CORE_SECURITY_INTEGRITY_CHECKER_H
#define CORE_SECURITY_INTEGRITY_CHECKER_H

#include <string>
#include <vector>

enum class IntegrityStatus {
    Unknown = 0,
    OK,
    MissingManifest,
    HMACMismatch,
    HashMismatch,
    Error,
};

struct IntegrityReport {
    IntegrityStatus status = IntegrityStatus::Unknown;
    std::string message;
};

/**
 * IntegrityChecker verifies vault integrity using MANIFEST.json and MANIFEST.hmac
 *
 * Layout (under vault root, currently ./data):
 *      data/
 *          vault.meta
 *          vault_store/
 *              index.json
 *              record_*.bin
 *          MANIFEST.json       <-- contains list of files + their sha256 (hex)
 *          MANIFEST.hmac       <-- HMAC-SHA256 (MANIFEST.json, key = VMK)
 */
class IntegrityChecker {
public:
    // Verify integrity under 'root' (usually "data") using VMK for HMAC
    // Returns report with status/message. Does not throw; converts to Error.
    static IntegrityReport verify(const std::string &root, const std::vector<unsigned char> &vmk);
};

#endif //CORE_SECURITY_INTEGRITY_CHECKER_H
