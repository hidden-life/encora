#ifndef CORE_STORAGE_STORAGE_ERROR_H
#define CORE_STORAGE_STORAGE_ERROR_H

#include <stdexcept>

class StorageError final : public std::runtime_error {
public:
    explicit StorageError(const std::string &err) : std::runtime_error(err) {};
};

#endif //CORE_STORAGE_STORAGE_ERROR_H
