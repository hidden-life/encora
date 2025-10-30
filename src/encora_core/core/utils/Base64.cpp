#include "Base64.h"

namespace {
    static const char table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
}

namespace Base64 {
    std::string encode(const std::vector<unsigned char> &data) {
        std::string output;
        int val = 0, valB = -6;
        for (const unsigned char c : data) {
            val = (val << 8) + c;
            valB += 8;
            while (valB >= 0) {
                output.push_back(table[(val >> valB) & 0x3F]);
                valB -= 6;
            }
        }

        if (valB > -6) {
            output.push_back(table[((val << 8) >> (valB + 8) & 0x3F)]);
        }

        while (output.size() % 4) {
            output.push_back('=');
        }

        return output;
    }

    std::vector<unsigned char> decode(const std::string &input) {
        std::vector<int> T(256, -1);
        for (int i = 0; i < 64; i++) {
            T[table[i]] = i;
        }

        std::vector<unsigned char> output;
        int val = 0, valB = -8;
        for (const unsigned char c : input) {
            if (T[c] == -1) break;
            val = (val << 6) + T[c];
            valB += 6;
            if (valB >= 0) {
                output.push_back(static_cast<unsigned char>((val >> valB) & 0xFF));
                valB -= 8;
            }
        }

        return output;
    }
}