#include "VaultMetadataIO.h"

#include <stdexcept>

#include "utils/Logger.h"

// TEMPORARY:
// in-memory singleton to simulate persistence
static bool g_hasMetadata = false;
static VaultMetadata g_metaMem;

VaultMetadata VaultMetadataIO::load(const std::string &path) {
    (void)path;

    if (!g_hasMetadata) {
        throw std::runtime_error("VaultMetadataIO::load: No metadata loaded (vault not initialized).");
    }

    EncoraLogger::Logger::log(EncoraLogger::Level::Info, "VaultMetadataIO::load called (stub).");

    return g_metaMem;
}

void VaultMetadataIO::save(const std::string &path, const VaultMetadata &meta) {
    (void)path;

    g_metaMem = meta;
    g_hasMetadata = true;

    EncoraLogger::Logger::log(EncoraLogger::Level::Info, "VaultMetadataIO::save called (stub).");
}