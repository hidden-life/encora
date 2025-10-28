#include "LocalEncryptedStorage.h"

bool LocalEncryptedStorage::save(const std::string &id, const std::vector<unsigned char> &data) {
    m_memory[id] = data;
    return true;
}

std::optional<std::vector<unsigned char> > LocalEncryptedStorage::load(const std::string &id) {
    const auto it = m_memory.find(id);
    if (it == m_memory.end()) {
        return std::nullopt;
    }

    return it->second;
}
