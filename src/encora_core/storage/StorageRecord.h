#ifndef CORE_STORAGE_STORAGE_RECORD_H
#define CORE_STORAGE_STORAGE_RECORD_H

#include <string>
#include <vector>
#include <chrono>

struct StorageRecord {
    std::string id;
    std::string name;
    std::string type;
    std::vector<unsigned char> nonce;
    std::vector<unsigned char> cipherText;
    std::chrono::system_clock::time_point createdAt;
    std::chrono::system_clock::time_point updatedAt;
};

#endif //CORE_STORAGE_STORAGE_RECORD_H
