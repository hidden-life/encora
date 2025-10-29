#include <sodium.h>
#include <stdexcept>

#include "KeyWrap.h"

#include "utils/Logger.h"

static constexpr std::size_t ENCORA_VMK_SIZE = 32; // 256 bits: 32 bytes * 8 bits
static constexpr std::size_t ENCORA_AEAD_KEY_SIZE = crypto_aead_xchacha20poly1305_ietf_KEYBYTES; // 32
static constexpr std::size_t ENCORA_AEAD_NONCE_SIZE = crypto_aead_xchacha20poly1305_ietf_NPUBBYTES; // 24

WrappedKey KeyWrap::wrap(const std::vector<unsigned char> &vmk, const std::vector<unsigned char> &derived) {
    if (sodium_init() < 0) {
        throw std::runtime_error("KeyWrap::wrap: sodium_init() failed.");
    }

    if (vmk.size() != ENCORA_VMK_SIZE) {
        throw std::runtime_error("KeyWrap::wrap: wrong size of VMK.");
    }

    if (derived.size() != ENCORA_AEAD_KEY_SIZE) {
        throw std::runtime_error("KeyWrap::wrap: wrong size of derived key.");
    }

    WrappedKey out;
    out.nonce.resize(ENCORA_AEAD_NONCE_SIZE);
    randombytes_buf(out.nonce.data(), out.nonce.size());

    // cipherText size = plainText size + MAC size
    std::vector<unsigned char> cipherText(vmk.size() + crypto_aead_xchacha20poly1305_ietf_ABYTES);
    unsigned long long cipherTextLength = 0;

    const int r = crypto_aead_xchacha20poly1305_ietf_encrypt(
        cipherText.data(),
        &cipherTextLength,
        vmk.data(), // plain text
        vmk.size(),
        nullptr, // no AAD for now
        0,
        nullptr, // no secret nonce other than NPUB
        out.nonce.data(), // public nonce
        derived.data() // key
        );

    if (r != 0) {
        throw std::runtime_error("KeyWrap::wrap: encrypt failed.");
    }

    cipherText.resize(static_cast<size_t>(cipherTextLength));
    out.cipherText = std::move(cipherText);

    EncoraLogger::Logger::log(EncoraLogger::Level::Debug, "VMK wrapped with XChaCha20-Poly1305 (sealed).");

    return out;
}

std::vector<unsigned char> KeyWrap::unwrap(const WrappedKey &wrapped, const std::vector<unsigned char> &derived) {
    if (sodium_init() < 0) {
        throw std::runtime_error("KeyWrap::unwrap: sodium_init() failed.");
    }

    if (wrapped.nonce.size() != ENCORA_AEAD_NONCE_SIZE) {
        throw std::runtime_error("KeyWrap::unwrap: wrong size of nonce.");
    }

    if (derived.size() != ENCORA_AEAD_KEY_SIZE) {
        throw std::runtime_error("KeyWrap::unwrap: wrong size of derived.");
    }

    std::vector<unsigned char> plainText(ENCORA_VMK_SIZE);
    unsigned long long decryptedLength = 0;

    const int r = crypto_aead_xchacha20poly1305_ietf_decrypt(
        plainText.data(),
        &decryptedLength,
        nullptr,
        wrapped.cipherText.data(),
        wrapped.cipherText.size(),
        nullptr,
        0,
        wrapped.nonce.data(),
        derived.data()
    );

    if (r != 0) {
        throw std::runtime_error("KeyWrap::unwrap: decrypt failed (wrong password or tampered data).");
    }

    if (decryptedLength != ENCORA_VMK_SIZE) {
        throw std::runtime_error("KeyWrap::unwrap: unexpected VMK length.");
    }

    EncoraLogger::Logger::log(EncoraLogger::Level::Debug, "VMK successfully unwrapped and authenticated.");

    return plainText;
}
