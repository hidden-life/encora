#ifndef CORE_TYPES_SECURE_BUFFER_H
#define CORE_TYPES_SECURE_BUFFER_H

#include <vector>

template<typename T>
class SecureBuffer {
public:
    SecureBuffer() = default;
    explicit SecureBuffer(std::size_t n) : m_buffer(n) {}

    std::vector<T> &data() { return m_buffer; }
    const std::vector<T> &data() const { return m_buffer; }

    std::size_t size() const { return m_buffer.size(); }

private:
    std::vector<T> m_buffer;
};

#endif //CORE_TYPES_SECURE_BUFFER_H
